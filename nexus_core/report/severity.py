"""Deterministic severity heuristic (no LLM, no network).

The report must be *fail-safe*: when no model is available the severity of a
finding still has to be stable and explainable. Every rule here is a pure
function of the observation the toolkit recorded, and the returned level is one
of :data:`nexus_core.report.models.SEVERITY_ORDER`.

The heuristic never escalates on its own: a tool that declares a severity
(nuclei templates do) always wins, and an unknown context degrades to ``info``
instead of inventing risk.
"""

from __future__ import annotations

from typing import Any

from .models import SEVERITY_ORDER

#: Ports whose service is treated as legacy/high-noise surface.
LEGACY_SERVICES: frozenset[str] = frozenset(
    {"telnet", "ftp", "smb", "microsoft-ds", "netbios-ssn", "rlogin", "vnc", "tftp"}
)
LEGACY_PORTS: frozenset[int] = frozenset({21, 23, 139, 445, 512, 513, 514, 5900, 69})
#: Services that are normal, expected exposure.
ROUTINE_SERVICES: frozenset[str] = frozenset(
    {"http", "https", "ssh", "smtp", "imap", "imaps", "pop3", "pop3s", "domain"}
)
ROUTINE_PORTS: frozenset[int] = frozenset({22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995})

#: Commands whose success means the operator reached credentials/root.
CRITICAL_COMMANDS: frozenset[str] = frozenset(
    {"hashdump", "getsystem", "lsa_secrets", "creds_all", "kiwi", "mimikatz"}
)
#: Commands that are plain situational awareness.
INFO_COMMANDS: frozenset[str] = frozenset(
    {"id", "whoami", "uname", "hostname", "sysinfo", "systeminfo", "ver", "ps",
     "tasklist", "getuid", "getpid", "pwd", "ls", "dir"}
)
#: Commands that change the target (privilege escalation, injection).
HIGH_COMMANDS: frozenset[str] = frozenset({"migrate", "getprivs", "shell", "execute"})

#: Statuses that mean the toolkit observed the requested outcome.
SUCCESS_STATUSES: frozenset[str] = frozenset({"ok", "session_opened", "completed", "success"})


def normalize_severity(value: Any, *, default: str = "info") -> str:
    """Clamp an arbitrary value to a known severity level."""
    text = str(value or "").strip().lower()
    return text if text in SEVERITY_ORDER else default


def severity_from_nuclei(value: Any) -> str:
    """Map a nuclei template severity (``unknown`` included) to ours."""
    return normalize_severity(value, default="info")


def _port_number(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def severity_for_port(port: dict[str, Any] | None) -> str:
    """Severity of one open nmap port: legacy surface, routine or unknown."""
    record = port if isinstance(port, dict) else {}
    service = str(record.get("service") or "").strip().lower()
    number = _port_number(record.get("port"))
    if service in LEGACY_SERVICES or (number is not None and number in LEGACY_PORTS):
        return "medium"
    if service in ROUTINE_SERVICES or (number is not None and number in ROUTINE_PORTS):
        return "info"
    # An open port we cannot classify is still *surface*, never a finding on
    # its own: keep it informational so the report stays conservative.
    return "info"


def highest_severity(severities: Any) -> str:
    """Return the most severe value of an iterable (``info`` when empty)."""
    best = "info"
    for value in severities or ():
        candidate = normalize_severity(value)
        if SEVERITY_ORDER.index(candidate) < SEVERITY_ORDER.index(best):
            best = candidate
    return best


def severity_for_command(command: str, status: str = "ok") -> str:
    """Severity of one command executed inside a session.

    A command that never ran (:data:`SUCCESS_STATUSES`) carries no severity of
    its own: the report records it as context, not as compromise.
    """
    if str(status or "").lower() not in SUCCESS_STATUSES:
        return "info"
    head = str(command or "").strip().splitlines()
    token = ""
    if head:
        token = head[0].strip().lower().split(" ", 1)[0]
    token = token.split("(", 1)[0]
    if token in CRITICAL_COMMANDS:
        return "critical"
    if token in HIGH_COMMANDS:
        return "high"
    if token in INFO_COMMANDS:
        return "info"
    return "low"


def severity_for_ffuf(status: Any) -> str:
    """Severity of one ffuf match: a protected endpoint reveals its existence."""
    number = _port_number(status)
    if number in {401, 403}:
        return "low"
    return "info"


def infer_severity(finding_context: dict[str, Any]) -> str:
    """Deterministic severity of one observation.

    ``finding_context`` keys understood (all optional except ``kind``):

    ``kind``              one of the classification strings of the extractor
    ``status``            ``session_opened``/``ok``/``failed``/...
    ``command``           command sent into a session
    ``template_severity`` severity declared by a nuclei template
    ``http_status``       ffuf match status
    ``port``              nmap port dict
    ``os_shell``          nmap ``shell`` socket that yielded a session
    """
    context = finding_context if isinstance(finding_context, dict) else {}
    kind = str(context.get("kind") or "")
    if kind == "session_opened":
        return "critical"
    if kind == "endpoint_protected":
        return "low"
    if kind == "subdomains":
        return "info"
    if kind == "http_surface":
        return "info"
    if kind == "nuclei":
        return severity_from_nuclei(context.get("template_severity"))
    if kind == "ffuf_match":
        return severity_for_ffuf(context.get("http_status"))
    if kind == "session_command":
        return severity_for_command(
            str(context.get("command") or ""), str(context.get("status") or "ok")
        )
    if kind == "open_ports":
        return severity_for_port(context.get("port"))
    return "info"


__all__ = [
    "CRITICAL_COMMANDS",
    "HIGH_COMMANDS",
    "INFO_COMMANDS",
    "LEGACY_PORTS",
    "LEGACY_SERVICES",
    "ROUTINE_PORTS",
    "ROUTINE_SERVICES",
    "highest_severity",
    "infer_severity",
    "normalize_severity",
    "severity_for_command",
    "severity_for_ffuf",
    "severity_for_port",
    "severity_from_nuclei",
]
