"""Shared builders for the report tests.

They write the *same* durable records the real toolkit writes: one ReAct
observation per tool call (carrying the full ``ToolResult``) plus the
hash-chained audit events the gateway emits. Nothing bypasses the store, so the
extractor is exercised against genuine data.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from nexus_core.agent import memory
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore

TENANT = "system"
AGENT = "omni"
LAB_SCOPE_CIDRS = ("203.0.113.0/24",)
LAB_SCOPE_DOMAINS = ("scanme.example",)
LAB_TARGET = "203.0.113.10"
LAB_DOMAIN = "scanme.example"


def iso(delta: timedelta = timedelta(0)) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def make_store(tmp_path) -> ControlStore:
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return store


def lab_scope(
    engagement_id: str = "eng-lab",
    *,
    cidrs=LAB_SCOPE_CIDRS,
    domains=LAB_SCOPE_DOMAINS,
    exclusions=(),
    owner_id: str = "operator-1",
    client: str = "ACME",
    name: str = "lab-engagement",
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> EngagementScope:
    return EngagementScope(
        engagement_id=engagement_id,
        tenant_id=TENANT,
        name=name,
        client=client,
        owner_id=owner_id,
        valid_from=valid_from or iso(-timedelta(days=1)),
        valid_until=valid_until or iso(timedelta(days=1)),
        cidrs=tuple(cidrs),
        domains=tuple(domains),
        urls=(),
        exclusions=tuple(exclusions),
        notes="entorno de laboratorio",
        created_at=iso(),
    )


def seed_engagement(store: ControlStore, scope: EngagementScope | None = None) -> EngagementScope:
    value = scope or lab_scope()
    EngagementStore(store).create(value)
    return value


def add_run(store: ControlStore, *, tenant_id: str = TENANT, objective: str = "lab") -> str:
    return str(store.create_run(tenant_id, {"source": "test", "objective": objective})["id"])


def result(
    output: dict[str, Any] | None = None,
    *,
    verified: bool = True,
    verification_method: str = "test",
    evidence: dict[str, Any] | None = None,
    exit_code: int | None = 0,
) -> dict[str, Any]:
    """Fake ``ToolResult.to_dict()`` with a realistic shape."""
    return {
        "success": verified,
        "output": output or {},
        "verified": verified,
        "verification_method": verification_method,
        "evidence": evidence or {},
        "exit_code": exit_code,
        "accepted_exit_codes": [0, 1],
        "stdout": "",
        "stderr": "",
        "timed_out": False,
    }


def record(
    store: ControlStore,
    run_id: str,
    tool_id: str,
    arguments: dict[str, Any],
    tool_result: dict[str, Any],
    *,
    engagement_id: str | None = None,
    tenant_id: str = TENANT,
    at: str | None = None,
    audit: bool = True,
) -> str:
    """Persist one tool call exactly like the loop/REPL does; return the message id."""
    conversation_id = memory.ensure_conversation(store, tenant_id, run_id, AGENT)
    output = tool_result.get("output") if isinstance(tool_result, dict) else None
    payload = {
        "tool_id": tool_id,
        "success": bool((tool_result or {}).get("success")),
        "verification_method": (tool_result or {}).get("verification_method"),
        "evidence": (tool_result or {}).get("evidence"),
        "output": output if isinstance(output, dict) else {},
    }
    message_id = memory.append_step(
        store,
        tenant_id,
        conversation_id,
        "user",
        json.dumps(payload, default=str),
        {
            "kind": "react.observation",
            "tool_id": tool_id,
            "arguments": dict(arguments or {}),
            "success": payload["success"],
            "tool_result": {
                key: value for key, value in payload.items() if key not in {"evidence", "output"}
            },
            "run_id": run_id,
        },
    )
    if at:
        set_message_time(store, message_id, at)
    if audit:
        writer = AuditWriter(store)
        event_payload: dict[str, Any] = {"argument_keys": sorted(arguments or {})}
        if engagement_id:
            event_payload["engagement_id"] = engagement_id
        writer.append(
            tenant_id=tenant_id,
            trace_id=run_id,
            actor_id=f"agent:{AGENT}",
            action="tool.invoke",
            resource_type="tool",
            resource_id=tool_id,
            payload=event_payload,
            decision="allow",
        )
        writer.append(
            tenant_id=tenant_id,
            trace_id=run_id,
            actor_id=f"agent:{AGENT}",
            action="tool.complete" if payload["success"] else "tool.failed",
            resource_type="tool",
            resource_id=tool_id,
            payload={"run_id": run_id, "output_bytes": len(json.dumps(payload))},
            decision="allow" if payload["success"] else "error",
        )
    return message_id


def audit(
    store: ControlStore,
    *,
    run_id: str,
    action: str,
    tool_id: str = "",
    target: str = "",
    payload: dict[str, Any] | None = None,
    decision: str = "allow",
    resource_type: str = "tool",
    resource_id: str | None = None,
    tenant_id: str = TENANT,
) -> str:
    """Append one audit event (chain of custody, scope denials, session commands)."""
    body = dict(payload or {})
    if target:
        body.setdefault("target", target)
    return AuditWriter(store).append(
        tenant_id=tenant_id,
        trace_id=run_id,
        actor_id=f"agent:{AGENT}",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id if resource_id is not None else tool_id,
        payload=body,
        decision=decision,
    )


def set_message_time(store: ControlStore, message_id: str, created_at: str) -> None:
    """Rewrite one message timestamp (used to exercise the dedup window)."""
    with store.connect() as conn:
        conn.execute(
            "UPDATE kernel_messages SET created_at=? WHERE id=?", (created_at, message_id)
        )


# ----------------------------------------------------------- tool output builders
def nmap_output(
    target: str = LAB_TARGET,
    ports: tuple[tuple[str, str], ...] = (("22", "ssh"), ("80", "http")),
    *,
    hosts_up: int = 1,
) -> dict[str, Any]:
    return {
        "target": target,
        "noise_level": "low",
        "scan": {
            "scanner": "nmap",
            "args": f"nmap -sV -oX - {target}",
            "started_at": "2026-09-29 14:20:11",
            "ended_at": "2026-09-29 14:20:41",
            "elapsed_seconds": 30.0,
            "hosts_up": hosts_up,
            "hosts_down": 0,
            "hosts": [
                {
                    "ip": target,
                    "hostname": "",
                    "state": "up",
                    "ports": [
                        {
                            "port": number,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service,
                            "product": "",
                            "version": "",
                            "extra_info": "",
                        }
                        for number, service in ports
                    ],
                    "os_matches": [],
                    "extraports": {},
                }
            ],
            "warnings": [],
            "raw_xml_sha256": "a" * 64,
        },
    }


def nuclei_output(findings: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    return {
        "targets_requested": 1,
        "noise_level": "medium",
        "count": len(findings),
        "findings": list(findings),
    }


def nuclei_finding(
    template_id: str = "CVE-2021-41773",
    name: str = "Apache 2.4.49 path traversal",
    severity_value: str = "high",
    *,
    matched_at: str = f"http://{LAB_TARGET}/",
    tags: tuple[str, ...] = ("cve-2021-41773", "apache", "lfi"),
    matcher_name: str = "http",
) -> dict[str, Any]:
    return {
        "template_id": template_id,
        "name": name,
        "severity": severity_value,
        "host": LAB_TARGET,
        "matched_at": matched_at,
        "type": "http",
        "tags": list(tags),
        "matcher_name": matcher_name,
        "extracted": [],
    }


def subfinder_output(domain: str = LAB_DOMAIN, subdomains: tuple[str, ...] = ()) -> dict[str, Any]:
    found = subdomains or tuple(f"host{i}.{domain}" for i in range(1, 4))
    return {
        "domain": domain,
        "noise_level": "low",
        "count": len(found),
        "subdomains": list(found),
        "sources": ["crtsh", "dnsdumpster"],
    }


def ffuf_output(url: str = f"http://{LAB_TARGET}", matches: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
    body = matches or (
        {"url": f"{url}/admin", "host": LAB_TARGET, "status": 200, "length": 120,
         "words": 10, "lines": 5, "content_type": "text/html",
         "redirect_location": "", "duration_ms": 12, "input": {}},
        {"url": f"{url}/.git", "host": LAB_TARGET, "status": 403, "length": 0,
         "words": 0, "lines": 0, "content_type": "text/html",
         "redirect_location": "", "duration_ms": 8, "input": {}},
    )
    return {"url": url, "noise_level": "medium", "count": len(body), "matches": list(body)}


def exploit_output(
    status: str = "session_opened",
    *,
    module: str = "exploit/linux/http/apache_mod_cgi_bash_env_exec",
    target: str = LAB_TARGET,
    session_uuid: str = "abc12345",
) -> dict[str, Any]:
    session = (
        {
            "uuid": session_uuid,
            "type": "shell",
            "tunnel_local": "127.0.0.1:4444",
            "tunnel_peer": f"{target}:51234",
            "via_exploit": module,
            "via_payload": "linux/x64/shell_reverse_tcp",
            "session_host": target,
            "session_port": 51234,
            "target_host": target,
            "username": "www-data",
            "info": "Command shell",
        }
        if status == "session_opened"
        else None
    )
    return {
        "module": module,
        "target": target,
        "status": status,
        "session": session,
        "job_uuid": "job-uuid-1",
        "raw_sha256": "b" * 64,
        "duration_seconds": 3.2,
    }


def session_output(
    command: str = "id",
    *,
    text: str = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
    status: str = "ok",
    session_uuid: str = "abc12345",
) -> dict[str, Any]:
    return {
        "session_uuid": session_uuid,
        "command": command,
        "status": status,
        "output": text,
        "output_bytes": len(text.encode()),
        "duration_seconds": 0.4,
        "raw_sha256": "c" * 64,
    }


def seed_full_engagement(tmp_path):
    """Record a realistic engagement: recon, web, an exploit and its follow-up.

    Returns ``(store, engagement, run_id)``. Every record goes through the same
    durable write path the toolkit uses, so a report built from it contains real
    findings and one failed attempt.
    """
    store = make_store(tmp_path)
    engagement = seed_engagement(store)
    run_id = add_run(store, objective="laboratorio completo")
    record(
        store,
        run_id,
        "nexus.recon.nmap",
        {"target": LAB_TARGET, "ports": "22,80"},
        result(
            nmap_output(),
            verification_method="nmap_xml_parsed",
            evidence={"hosts_up": 1, "ports_open_total": 2, "raw_xml_sha256": "a" * 64},
        ),
    )
    record(
        store,
        run_id,
        "nexus.recon.subfinder",
        {"domain": LAB_DOMAIN},
        result(
            subfinder_output(),
            verification_method="subfinder_jsonl_parsed",
            evidence={"count": 3, "raw_sha256": "e" * 64},
        ),
    )
    record(
        store,
        run_id,
        "nexus.web.nuclei",
        {"targets": [LAB_TARGET], "severity": ["low", "medium", "high"]},
        result(
            nuclei_output((nuclei_finding(),)),
            verification_method="nuclei_jsonl_parsed",
            evidence={"count": 1, "raw_sha256": "d" * 64},
        ),
    )
    record(
        store,
        run_id,
        "nexus.web.ffuf",
        {"url": f"http://{LAB_TARGET}/FUZZ"},
        result(
            ffuf_output(),
            verification_method="ffuf_json_parsed",
            evidence={"count": 2, "raw_sha256": "f" * 64},
        ),
    )
    record(
        store,
        run_id,
        "nexus.exploit.msf_exploit",
        {"module": "exploit/multi/handler", "target": LAB_TARGET},
        result(
            exploit_output("timeout", module="exploit/multi/handler"),
            verification_method="msf_exploit_timeout",
            evidence={"module": "exploit/multi/handler", "target": LAB_TARGET},
        ),
    )
    record(
        store,
        run_id,
        "nexus.exploit.msf_exploit",
        {
            "module": "exploit/linux/http/apache_mod_cgi_bash_env_exec",
            "target": LAB_TARGET,
        },
        result(
            exploit_output(),
            verification_method="msf_exploit_session_opened",
            evidence={"module": "m", "target": LAB_TARGET, "session_uuid": "abc12345"},
        ),
    )
    record(
        store,
        run_id,
        "nexus.session.interact",
        {"session_uuid": "abc12345", "command": "id"},
        result(session_output("id"), verification_method="msf_session_interact_ok"),
        engagement_id=engagement.engagement_id,
    )
    record(
        store,
        run_id,
        "nexus.session.interact",
        {"session_uuid": "abc12345", "command": "hashdump"},
        result(
            session_output("hashdump", text="Administrator:500:aad3b435b51404eeaad3b435b51404ee:...\n"),
            verification_method="msf_session_interact_ok",
        ),
        engagement_id=engagement.engagement_id,
    )
    audit(
        store,
        run_id=run_id,
        action="scope.denied",
        tool_id="nexus.recon.nmap",
        payload={
            "target_keys": ["target"],
            "reason": "ScopeViolation(example.com): target is outside the engagement",
        },
        decision="deny",
    )
    return store, engagement, run_id


__all__ = [
    "AGENT",
    "LAB_DOMAIN",
    "LAB_TARGET",
    "TENANT",
    "add_run",
    "audit",
    "exploit_output",
    "ffuf_output",
    "iso",
    "lab_scope",
    "make_store",
    "nmap_output",
    "nuclei_finding",
    "nuclei_output",
    "record",
    "result",
    "seed_engagement",
    "seed_full_engagement",
    "session_output",
    "set_message_time",
    "subfinder_output",
]
