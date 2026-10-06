"""Extract findings from the durable record (audit trail + persisted ToolResults).

Two durable sources are read, never the target:

* ``kernel_audit_events`` — the hash-chained trail: what was authorized, what was
  denied, what completed and what failed, plus the session commands the REPL
  recorded. Its ``trace_id`` is the run id.
* ``kernel_messages`` — the persisted ReAct observations. These carry the full
  ``ToolResult`` (``output`` + ``evidence``) that the audit payload intentionally
  trims to keep the chain small. A message's ``metadata.kind == "react.observation"``
  and its body is the JSON ``{"tool_id", "success", "verification_method",
  "evidence", "output"}``.

An observation only becomes a :class:`Finding` when the toolkit *verified* it. A
denied scope, a failed tool or an exploit that opened no session becomes a
:class:`FailedAttempt` instead, and is rendered separately so a reader can tell
"we tried and it did not work" from "we never looked".

Attribution: a run belongs to an engagement when one of its observations targeted
something inside the engagement scope (matched offline, no DNS) or when one of
its audit events declares that ``engagement_id`` (the REPL's ``session.command``
events do). Session commands carry no target of their own and therefore inherit
the run's attribution.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import utc_now
from nexus_core.scope import EngagementScope, EngagementStore

from . import cve_enrichment as cve_module
from . import cvss as cvss_module
from . import cvss4 as cvss4_module
from . import frameworks as frameworks_module
from . import mitre, severity
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


#: Audit actions that close one tool call.
_COMPLETION_ACTIONS = frozenset({"tool.complete", "tool.failed", "session.command"})


@dataclass
class _Context:
    """Everything the per-tool builders need."""

    scope: EngagementScope
    event_by_run: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    artifact_refs: list[dict[str, Any]] = field(default_factory=list)
    #: ``(run_id, tool_id) -> [completion events]`` in trail order, so the Nth
    #: observation of a tool is tied to the Nth completion of that tool.
    completion_by_key: dict[tuple[str, str], list[dict[str, Any]]] = field(
        default_factory=dict
    )

    def completion_event(self, observation: Observation) -> dict[str, Any] | None:
        """The audit event that closed this exact observation, when known."""
        events = self.completion_by_key.get((observation.run_id, observation.tool_id)) or []
        if observation.ordinal < len(events):
            return events[observation.ordinal]
        return None


# ------------------------------------------------------------------ scope match
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


# ------------------------------------------------------------------- loaders
def _load_events(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    try:
        return list(AuditWriter(store).export(tenant_id))
    except Exception:  # noqa: BLE001 - a report is better than an exception
        return []


def _load_messages(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Read every conversation message of the tenant, oldest first."""
    try:
        with store.connect() as conn:
            rows = conn.execute(
                """
                SELECT m.sequence, m.id, m.run_id, m.role, m.content, m.metadata,
                       m.created_at
                FROM kernel_messages m
                JOIN kernel_conversations c ON c.id = m.conversation_id
                WHERE m.tenant_id=? AND c.status!='deleted'
                ORDER BY m.sequence
                """,
                (tenant_id,),
            ).fetchall()
    except Exception:  # noqa: BLE001
        return []
    values = []
    for row in rows:
        value = dict(row)
        try:
            value["metadata"] = json.loads(value.get("metadata") or "{}")
        except (TypeError, ValueError):
            value["metadata"] = {}
        values.append(value)
    return values


def _load_artifacts(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    try:
        with store.connect() as conn:
            rows = conn.execute(
                """SELECT id, run_id, media_type, sha256, size_bytes, created_at
                FROM kernel_artifacts WHERE tenant_id=? ORDER BY created_at""",
                (tenant_id,),
            ).fetchall()
    except Exception:  # noqa: BLE001
        return []
    return [dict(row) for row in rows]


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


_VIOLATION_TARGET = re.compile(r"ScopeViolation\(([^)]+)\)")


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


def _select_runs(
    events: list[dict[str, Any]],
    observations: list[Observation],
    scope: EngagementScope,
    run_ids: list[str] | None,
) -> set[str]:
    if run_ids is not None:
        return {str(item) for item in run_ids}
    selected = _run_targets(observations, scope)
    for event in events:
        payload = event.get("payload") or {}
        if str(payload.get("engagement_id") or "") == scope.engagement_id:
            # The REPL records ``session.command`` with the live engagement, and
            # a session command has no target of its own to match against.
            selected.add(str(event.get("trace_id") or ""))
    selected.discard("")
    return selected


# ---------------------------------------------------------------- evidence
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


# ------------------------------------------------------------- per-tool builders
def _nmap_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    scan = output.get("scan") if isinstance(output.get("scan"), dict) else {}
    hosts = scan.get("hosts") if isinstance(scan.get("hosts"), list) else []
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


def _nuclei_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    findings = output.get("findings") if isinstance(output.get("findings"), list) else []
    results: list[Finding] = []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            continue
        template_id = str(item.get("template_id") or "")
        name = str(item.get("name") or template_id or "hallazgo de nuclei")
        target = str(item.get("matched_at") or item.get("host") or "")
        tags = [str(tag) for tag in (item.get("tags") or ())]
        cve = next(
            (tag.upper() for tag in tags if tag.lower().startswith("cve-")), None
        )
        cwe = next(
            (
                tag.upper().replace("CWE-", "CWE-")
                for tag in tags
                if tag.lower().startswith("cwe-")
            ),
            None,
        )
        results.append(
            Finding(
                finding_id=_finding_id("nuclei", observation, f"{index}:{template_id}"),
                # Severity is rendered from ``Finding.severity`` by every
                # renderer; promoting it into the title would duplicate it
                # ("### [HIGH] [HIGH] ...").
                title=name,
                description=(
                    f"Template `{template_id}` matcheó en {target or 'el objetivo'}. "
                    f"Tipo: {item.get('type') or 'n/d'}"
                    + (f". Matcher: {item.get('matcher_name')}" if item.get("matcher_name") else "")
                    + (". Extraído: " + ", ".join(str(x) for x in item.get("extracted") or ()) if item.get("extracted") else "")
                ),
                severity=severity.severity_from_nuclei(item.get("severity")),
                cvss_score=None,
                cvss_vector=None,
                cwe=cwe,
                cve=cve,
                mitre_techniques=(),
                owasp_category=None,
                affected_targets=tuple(filter(None, (target,))),
                evidence=_evidence_for(observation, context, excerpt=item),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"nuclei -t {template_id} -u {target}".strip(),
                    f"Revisar la línea JSON del template {template_id} en la evidencia",
                ),
                kind="nuclei",
            )
        )
    return results


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


def _ffuf_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    matches = output.get("matches") if isinstance(output.get("matches"), list) else []
    base_url = str(output.get("url") or "")
    exposed: list[str] = []
    protected: list[str] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        url = str(match.get("url") or base_url)
        status = match.get("status")
        if severity.severity_for_ffuf(status) == "low":
            protected.append(f"{url} [{status}]")
        else:
            exposed.append(f"{url} [{status}]")
    results: list[Finding] = []
    if exposed:
        results.append(
            Finding(
                finding_id=_finding_id("http_surface", observation),
                title=f"Endpoints descubiertos ({len(exposed)})",
                description=(
                    f"El fuzzing de {base_url or 'la URL'} encontró {len(exposed)} "
                    "recurso(s) accesible(s) (200/30x). Es superficie publicada."
                ),
                severity="info",
                cvss_score=None,
                cvss_vector=None,
                cwe=None,
                cve=None,
                mitre_techniques=(),
                owasp_category=None,
                affected_targets=tuple(exposed[:50]),
                evidence=_evidence_for(observation, context, excerpt=output),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"ffuf -u {base_url}/FUZZ -w <wordlist>",
                    "Revisar cada endpoint y su contenido en la evidencia",
                ),
                kind="http_surface",
            )
        )
    if protected:
        results.append(
            Finding(
                finding_id=_finding_id("endpoint_protected", observation),
                title=f"Endpoints protegidos descubiertos ({len(protected)})",
                description=(
                    f"El fuzzing de {base_url or 'la URL'} reveló {len(protected)} "
                    "recurso(s) que responden 401/403: la enumeración ya confirmó su "
                    "existencia aunque exija credenciales."
                ),
                severity="low",
                cvss_score=None,
                cvss_vector=None,
                cwe="CWE-200",
                cve=None,
                mitre_techniques=(),
                owasp_category="A01:2021-Broken Access Control",
                affected_targets=tuple(protected[:50]),
                evidence=_evidence_for(observation, context, excerpt=output),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"ffuf -u {base_url}/FUZZ -w <wordlist>",
                    "Confirmar que el recurso exige autenticación sin revelar contenido",
                ),
                kind="endpoint_protected",
            )
        )
    return results


def _exploit_findings(
    observation: Observation, context: _Context
) -> tuple[list[Finding], list[FailedAttempt]]:
    output = observation.output or {}
    status = str(output.get("status") or "")
    module = str(output.get("module") or "")
    target = str(output.get("target") or "")
    session = output.get("session") if isinstance(output.get("session"), dict) else {}
    if status == "session_opened":
        uuid = str((session or {}).get("uuid") or "")
        username = str((session or {}).get("username") or "")
        kind_session = str((session or {}).get("type") or "")
        finding = Finding(
            finding_id=_finding_id("session_opened", observation),
            title=f"Acceso obtenido vía {module or 'un exploit'}",
            description=(
                f"El módulo `{module}` abrió una sesión {kind_session or 'remota'} "
                f"({uuid or 'uuid n/d'}) sobre {target}"
                + (f" como `{username}`" if username else "")
                + ". El acceso está confirmado por el post-condition del handler, "
                "no por una afirmación del modelo."
            ),
            severity="critical",
            cvss_score=None,
            cvss_vector=None,
            cwe=None,
            cve=None,
            mitre_techniques=(),
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            affected_targets=tuple(filter(None, (target,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"Ejecutar `nexus.exploit.msf_exploit` con module=`{module}` y target=`{target}`",
                f"Comprobar la sesión con `nexus.session.list` (uuid {uuid or 'n/d'})",
            ),
            kind="session_opened",
        )
        return [finding], []
    if status in {"timeout", "failed", "no_session"}:
        reason = {
            "timeout": "el exploit terminó sin abrir sesión (dentro del tiempo concedido)",
            "failed": "el módulo no pudo ejecutarse contra el objetivo",
            "no_session": "el módulo completó y no abrió sesión",
        }[status]
        return [], [
            FailedAttempt(
                tool_id=observation.tool_id,
                target=target,
                reason=reason,
                attempted_at=observation.created_at,
                evidence=_evidence_for(observation, context, excerpt=output),
            )
        ]
    return [], []


def _session_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    command = str(output.get("command") or observation.arguments.get("command") or "")
    session_uuid = str(
        output.get("session_uuid") or observation.arguments.get("session_uuid") or ""
    )
    status = str(output.get("status") or "")
    if not command or status not in {"ok", "timeout"}:
        return []
    text = str(output.get("output") or "")
    level = severity.severity_for_command(command, status)
    return [
        Finding(
            finding_id=_finding_id("session_command", observation, command),
            title=f"Comando ejecutado en sesión: {command.strip()}",
            description=(
                f"Se ejecutó `{command.strip()}` en la sesión {session_uuid or 'n/d'} "
                f"(estado `{status}`) y devolvió {len(text)} bytes. "
                f"Salida: {text.strip()[:800] or '(vacía)'}"
            ),
            severity=level,
            cvss_score=None,
            cvss_vector=None,
            cwe=None,
            cve=None,
            mitre_techniques=mitre.techniques_for_command(command),
            owasp_category=None,
            affected_targets=tuple(filter(None, (session_uuid,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"Adjuntar la sesión {session_uuid or 'n/d'} (`/session attach {session_uuid}`)",
                f"Enviar `{command.strip()}` con `nexus.session.interact`",
            ),
            kind="session_command",
        )
    ]


# --------------------------------------------------- extended report builders
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


def _sqlmap_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    url = str(output.get("url") or "")
    results: list[Finding] = []
    for index, item in enumerate(_dict_list(output.get("findings"))):
        parameter = str(item.get("parameter") or "?")
        injection = str(item.get("injection_type") or "SQL injection")
        dbms = item.get("dbms")
        title = str(item.get("title") or f"SQL injection en parámetro `{parameter}`")
        results.append(
            Finding(
                finding_id=_finding_id("sqli", observation, f"{index}:{parameter}"),
                title=title,
                description=(
                    f"sqlmap confirmó una inyección SQL ({injection}) en el parámetro "
                    f"`{parameter}` ({str(item.get('method') or 'GET')}) de {url or 'el objetivo'}"
                    + (f", DBMS `{dbms}`" if dbms else "")
                    + f". Payload observado: `{str(item.get('payload') or '')[:300]}`"
                ),
                severity=severity.normalize_severity(item.get("severity"), default="high"),
                cvss_score=None,
                cvss_vector=None,
                cwe="CWE-89",
                cve=None,
                mitre_techniques=(),
                owasp_category="A03:2021-Injection",
                affected_targets=tuple(filter(None, (url,))),
                evidence=_evidence_for(observation, context, excerpt=item),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"sqlmap -u {url} --batch --flush-session".strip(),
                    f"Confirmar la inyección en el parámetro `{parameter}`",
                ),
                kind="sqli",
            )
        )
    return results


def _dalfox_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    target = str(output.get("target") or "")
    results: list[Finding] = []
    for index, item in enumerate(_dict_list(output.get("findings"))):
        url = str(item.get("url") or target)
        param = str(item.get("param") or "?")
        results.append(
            Finding(
                finding_id=_finding_id("xss", observation, f"{index}:{param}"),
                title=str(item.get("message") or f"XSS reflectido en parámetro `{param}`"),
                description=(
                    f"dalfox confirmó un XSS ({str(item.get('inject_type') or 'reflected')}) "
                    f"en el parámetro `{param}` de {url or 'el objetivo'}. Payload: "
                    f"`{str(item.get('payload') or '')[:300]}`. Evidencia: "
                    f"`{str(item.get('evidence') or '')[:300]}`"
                ),
                severity=severity.normalize_severity(item.get("severity"), default="medium"),
                cvss_score=None,
                cvss_vector=None,
                cwe=str(item.get("cwe") or "CWE-79"),
                cve=None,
                mitre_techniques=(),
                owasp_category="A03:2021-Injection",
                affected_targets=tuple(filter(None, (url,))),
                evidence=_evidence_for(observation, context, excerpt=item),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"dalfox url {url}".strip(),
                    f"Revisar el parámetro `{param}` y su vector de inyección",
                ),
                kind="xss",
            )
        )
    return results


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


def _searchsploit_reference(
    observation: Observation, context: _Context
) -> list[ReportItem]:
    output = observation.output or {}
    exploits = _dict_list(output.get("exploits"))
    shellcodes = _dict_list(output.get("shellcodes"))
    if not exploits and not shellcodes:
        return []
    query = str(output.get("query") or "")
    entries = exploits + shellcodes
    return [
        _report_item(
            kind="reference",
            title=f"Exploits disponibles para «{query}» ({len(entries)})",
            detail={
                "query": query,
                "total": output.get("total"),
                "exploits": exploits,
                "shellcodes": shellcodes,
            },
            observation=observation,
            context=context,
            targets=(str(item.get("edb_id") or "") for item in entries),
        )
    ]


def _netexec_surface(observation: Observation, context: _Context) -> list[ReportItem]:
    output = observation.output or {}
    entries = _dict_list(output.get("entries"))
    if not entries:
        return []
    protocol = str(output.get("protocol") or "")
    targets = [str(item) for item in (output.get("targets") or []) if item]
    if not targets and output.get("target"):
        targets = [str(output["target"])]
    return [
        _report_item(
            kind="surface",
            title=f"Superficie {protocol or 'red'} observada ({len(entries)} línea(s))",
            detail={
                "protocol": protocol,
                "targets": targets,
                "entries": entries,
            },
            observation=observation,
            context=context,
            targets=targets,
        )
    ]


def _bloodhound_evidence(
    observation: Observation, context: _Context
) -> list[ReportItem]:
    output = observation.output or {}
    files = _dict_list(output.get("files"))
    total_records = int(output.get("total_records") or 0)
    if not files and not total_records:
        return []
    dc = str(output.get("dc") or "")
    return [
        _report_item(
            kind="evidence",
            title=(
                f"Mapa de Active Directory recolectado "
                f"({len(files)} fichero(s), {total_records} registro(s))"
            ),
            detail={
                "domain": str(output.get("domain") or ""),
                "dc": dc,
                "total_records": total_records,
                "files": files,
            },
            observation=observation,
            context=context,
            targets=tuple(filter(None, (dc,))),
        )
    ]


def _secretsdump_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    entries = _dict_list(output.get("entries"))
    secrets = _dict_list(output.get("secrets"))
    if not entries and not secrets:
        return []
    target = str(output.get("target") or "")
    usernames = [str(item.get("username") or "") for item in entries]
    return [
        Finding(
            finding_id=_finding_id("credentials", observation),
            title=f"Credenciales volcadas ({len(entries)} cuenta(s))",
            description=(
                f"secretsdump extrajo material de autenticación de {target or 'el objetivo'}: "
                f"{len(entries)} cuenta(s) con hashes NTLM"
                + (f" ({', '.join(usernames[:20])})" if usernames else "")
                + (f" y {len(secrets)} secreto(s) LSA" if secrets else "")
                + f". Fuentes: {', '.join(str(source) for source in output.get('sources') or []) or 'n/d'}."
            ),
            severity="critical",
            cvss_score=None,
            cvss_vector=None,
            cwe="CWE-522",
            cve=None,
            mitre_techniques=("T1003.003",),
            owasp_category="A02:2021-Cryptographic Failures",
            affected_targets=tuple(filter(None, (target,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"secretsdump -target {target} (método {output.get('method') or 'n/d'})",
                "Confirmar el acceso con las credenciales obtenidas sin reutilizarlas fuera del alcance",
            ),
            kind="credentials",
        )
    ]


def _getuserspns_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    principals = _dict_list(output.get("service_principals"))
    hashes = _dict_list(output.get("hashes"))
    if not principals and not hashes:
        return []
    dc_ip = str(output.get("dc_ip") or "")
    names = [str(item.get("name") or item.get("service_principal_name") or "") for item in principals]
    return [
        Finding(
            finding_id=_finding_id("kerberoast", observation),
            title=f"Cuentas kerberoastables ({len(principals)})",
            description=(
                f"GetUserSPNs enumeró {len(principals)} cuenta(s) de servicio con SPN en "
                f"{output.get('domain') or 'el dominio'}"
                + (f" ({', '.join(names[:20])})" if names else "")
                + (f" y solicitó {len(hashes)} ticket(s) TGS (hash Kerberoast)" if hashes else "")
                + ". Un atacante puede crackearlos offline para escalar privilegios."
            ),
            severity="high",
            cvss_score=None,
            cvss_vector=None,
            cwe="CWE-522",
            cve=None,
            mitre_techniques=("T1558.003",),
            owasp_category="A02:2021-Cryptographic Failures",
            affected_targets=tuple(filter(None, (dc_ip,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"GetUserSPNs -dc-ip {dc_ip} -request".strip(),
                "Crackear los hashes TGS offline y validar las cuentas afectadas",
            ),
            kind="kerberoast",
        )
    ]


def _psexec_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    if not output.get("connected"):
        return []
    target = str(output.get("target") or "")
    command = str(output.get("command") or "")
    lines = [str(line) for line in (output.get("lines") or [])]
    return [
        Finding(
            finding_id=_finding_id("remote_exec", observation),
            title="Ejecución remota confirmada con psexec",
            description=(
                f"psexec ejecutó `{command or 'el comando'}` en {target or 'el objetivo'} "
                f"y devolvió {len(lines)} línea(s) de salida. La conexión remota está "
                "confirmada por la post-condition del handler."
            ),
            severity="critical",
            cvss_score=None,
            cvss_vector=None,
            cwe="CWE-284",
            cve=None,
            mitre_techniques=("T1021.002",),
            owasp_category=None,
            affected_targets=tuple(filter(None, (target,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"psexec -target {target} `{command}`".strip(),
                "Revisar la salida del comando remoto en la evidencia",
            ),
            kind="remote_exec",
        )
    ]


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge identical observations within :data:`DEDUP_WINDOW_SECONDS`."""
    merged: list[Finding] = []
    index: dict[tuple[str, str, tuple[str, ...]], Finding] = {}
    for finding in findings:
        key = (finding.kind, finding.title, finding.affected_targets)
        previous = index.get(key)
        if previous is not None and _within_window(previous.discovered_at, finding.discovered_at):
            from dataclasses import replace

            updated = replace(
                previous,
                reproductions=previous.reproductions + 1,
                evidence=previous.evidence + finding.evidence,
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


# ------------------------------------------------------------------- public API
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
    events = _load_events(store, tenant_id)
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
    events = _load_events(store, tenant_id)
    messages = _load_messages(store, tenant_id)
    observations, undecodable = _observations(messages)
    selected = _select_runs(events, observations, scope, run_ids)
    scoped_events = [
        event for event in events if str(event.get("trace_id") or "") in selected
    ]
    event_by_run: dict[str, list[dict[str, Any]]] = {}
    completion_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in scoped_events:
        run_id = str(event.get("trace_id") or "")
        event_by_run.setdefault(run_id, []).append(event)
        if str(event.get("action") or "") in _COMPLETION_ACTIONS:
            completion_by_key.setdefault(
                (run_id, str(event.get("resource_id") or "")), []
            ).append(event)
    return _Collection(
        scope=scope,
        events=events,
        scoped_events=scoped_events,
        observations=observations,
        selected=selected,
        context=_Context(
            scope=scope,
            event_by_run=event_by_run,
            artifact_refs=_load_artifacts(store, tenant_id),
            completion_by_key=completion_by_key,
        ),
        undecodable=undecodable,
    )


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
        if observation.tool_id == "nexus.recon.nmap":
            findings.extend(_nmap_findings(observation, context))
        elif observation.tool_id == "nexus.web.nuclei":
            findings.extend(_nuclei_findings(observation, context))
        elif observation.tool_id == "nexus.recon.subfinder":
            findings.extend(_subfinder_findings(observation, context))
        elif observation.tool_id == "nexus.web.ffuf":
            findings.extend(_ffuf_findings(observation, context))
        elif observation.tool_id == "nexus.exploit.msf_exploit":
            produced, attempts = _exploit_findings(observation, context)
            findings.extend(produced)
            failed.extend(attempts)
        elif observation.tool_id == "nexus.web.sqlmap":
            findings.extend(_sqlmap_findings(observation, context))
        elif observation.tool_id == "nexus.web.dalfox":
            findings.extend(_dalfox_findings(observation, context))
        elif observation.tool_id == "nexus.attack.impacket_secretsdump":
            findings.extend(_secretsdump_findings(observation, context))
        elif observation.tool_id == "nexus.attack.impacket_getuserspns":
            findings.extend(_getuserspns_findings(observation, context))
        elif observation.tool_id == "nexus.attack.impacket_psexec":
            findings.extend(_psexec_findings(observation, context))
        elif observation.tool_id == "nexus.session.interact":
            findings.extend(_session_findings(observation, context))

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
            if (str(event.get("trace_id") or ""), str(event.get("resource_id") or "")) in observed_failures:
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
    inventories: list[ReportItem] = []
    references: list[ReportItem] = []
    surfaces: list[ReportItem] = []
    evidences: list[ReportItem] = []
    for observation in collection.observations:
        if observation.run_id not in collection.selected or not observation.success:
            continue
        tool_id = observation.tool_id
        if tool_id == "nexus.recon.gobuster":
            inventories.extend(_gobuster_inventory(observation, collection.context))
        elif tool_id == "nexus.recon.whatweb":
            inventories.extend(_whatweb_inventory(observation, collection.context))
        elif tool_id == "nexus.exploit.searchsploit":
            references.extend(_searchsploit_reference(observation, collection.context))
        elif tool_id == "nexus.recon.netexec":
            surfaces.extend(_netexec_surface(observation, collection.context))
        elif tool_id == "nexus.recon.bloodhound_python":
            evidences.extend(_bloodhound_evidence(observation, collection.context))
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
        session = output.get("session") if isinstance(output.get("session"), dict) else {}
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
#: Events that open a tool call, in the order the trail wrote them.
_TIMELINE_OPENERS = frozenset({"tool.invoke", "react.step", "session.command"})


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
    findings, failed = await extract_findings(store, tenant_id, engagement_id, run_ids)
    if enrich_cves:
        findings = list(cve_module.enrich_findings(findings, root=cve_cache_dir))
    inventories, references, surfaces, evidences = await extract_report_items(
        store, tenant_id, engagement_id, run_ids
    )
    scored = attach_cvss(findings, llm_client if llm_cvss else None)
    scored = frameworks_module.attach_frameworks(scored)

    tools_used: list[str] = []
    for observation in collection.observations:
        if observation.run_id in collection.selected and observation.tool_id not in tools_used:
            tools_used.append(observation.tool_id)

    times = [
        str(event.get("created_at") or "") for event in collection.scoped_events
    ]
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

    report = EngagementReport(
        engagement_id=str(metadata["engagement_id"]),
        engagement_name=str(metadata["engagement_name"]),
        client=str(metadata["client"]),
        operator=str(metadata["operator"]),
        started_at=min(times) if times else str(metadata["valid_from"]),
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
