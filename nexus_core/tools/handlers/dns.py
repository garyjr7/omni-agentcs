"""Durable ``nexus.recon.dns`` handler: governed DNS queries with a parser.

Why this tool exists (measured in RUN_sala10 / RA2): the room's only reachable
flag lived in a ``TXT`` record of the domain, and the vulnerability the room
points at is *insecure dynamic DNS updates*. Reading that with ``dig`` by hand
left both outside scope, audit and deterministic verification.

This handler is **read-only**: it runs the resolved ``dig`` binary through the
sandbox, asks one server one name, and hands the output to the deterministic
parser. It never writes to the zone, so no update can be performed through it.
"""

from __future__ import annotations

from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.dns import empty_dns_result, parse_dig_output

from ._ad import ad_sandbox, resolve_ad_binary, validate_host
from ._exec import run_in_sandbox
from .workspace import workspace_root

DNS_BINARY_CANDIDATES = ("dig",)
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT", "PTR", "ANY")
DNS_DEFAULT_TIMEOUT_SECONDS = 30
DNS_MAX_TIMEOUT_SECONDS = 120

#: A query name: a DNS-style name or a ``_service._proto`` SRV label, no spaces.
_DNS_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._*")


def validate_dns_name(value: Any) -> str:
    """Return a single DNS owner name (no wildcards beyond a leading ``*``)."""
    text = str(value or "").strip().rstrip(".")
    if not text or len(text) > 253:
        raise ValueError("name is required and must be at most 253 characters")
    if any(ch not in _DNS_NAME_CHARS for ch in text):
        raise ValueError("name contains unsupported characters")
    if "*" in text[1:]:
        raise ValueError("only a leading wildcard is allowed")
    if ".." in text or text.startswith("."):
        raise ValueError("name has an empty label")
    return text


def validate_record_type(value: Any) -> str:
    """Return an upper-cased record type from the closed set."""
    text = str(value or "A").strip().upper()
    if text not in DNS_RECORD_TYPES:
        raise ValueError(f"unsupported record type: {text!r}")
    return text


def dns_query_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.dns``."""
    return ToolDefinition(
        tool_id="nexus.recon.dns",
        idempotent=True,
        name="DNS query",
        tenant_id=tenant_id,
        description=(
            "Consulta un servidor DNS dentro del scope: A/AAAA/CNAME/MX/NS/SOA/SRV/TXT/"
            "PTR/ANY. Devuelve la cabecera (status) y los registros observados con TTL y "
            "valor; extrae flags de tipo flag{fake_flag} en texto. Es el primitivo gobernado para "
            "loot en DNS y para el reconocimiento de zona."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "name": {"type": "string", "minLength": 1, "maxLength": 253},
                "record_type": {
                    "type": "string",
                    "enum": list(DNS_RECORD_TYPES),
                    "default": "A",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": DNS_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "name"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        effect="read_only",
        required_permissions=["execute:tool:nexus.recon.dns"],
        timeout_seconds=120,
        max_output_bytes=500_000,
        scope_target_field="target",
        scope_required=True,
        sandbox_required=True,
    )


async def dns_query_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Ask one DNS server one name and parse the answer deterministically."""
    target = validate_host(arguments.get("target"))
    name = validate_dns_name(arguments.get("name"))
    record_type = validate_record_type(arguments.get("record_type"))

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        DNS_MAX_TIMEOUT_SECONDS,
        max(5, int(requested_timeout) if requested_timeout else DNS_DEFAULT_TIMEOUT_SECONDS),
    )

    binary = resolve_ad_binary(*DNS_BINARY_CANDIDATES)
    if binary is None:
        raise RuntimeError("the 'dig' binary is not installed; install dnsutils and retry")

    # One server, one name, two tries, no search-list guessing: deterministic.
    argv = [
        binary,
        "+tries=2",
        f"+time={max(2, timeout_seconds // 3)}",
        "+noquestion",
        f"@{target}",
        name,
        record_type,
    ]
    evidence: dict[str, Any] = {
        "server": target,
        "name": name,
        "record_type": record_type,
        "noise_level": "low",
        "timeout_seconds": timeout_seconds,
    }
    sandbox = ad_sandbox(workspace_root(), binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_DNS_IMAGE",
        default_image="alpine:3.20",
    )

    payload = parse_dig_output(
        result.stdout or "",
        server=target,
        name=name,
        record_type=record_type,
        stderr=result.stderr or "",
    )
    evidence.update(
        {
            "status": payload["status"],
            "count": payload["count"],
            "records": payload["records"],
            "flags": payload["flags"],
            "dig_sha256": payload["dig_sha256"],
            "error": payload["error"],
        }
    )

    if result.timed_out:
        return ToolResult(
            output=empty_dns_result(target, name, record_type) | {"error": "dns query timed out"},
            verified=False,
            verification_method="dns_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    answered = payload["status"] is not None
    if answered:
        output = empty_dns_result(target, name, record_type)
        output.update(payload)
        return ToolResult(
            output=output,
            verified=True,
            # A well-formed answer is the post-condition, including ``NXDOMAIN``:
            # "the name does not exist" is a real observation, not a failure.
            verification_method="dns_response_parsed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    output = empty_dns_result(target, name, record_type)
    output.update(payload)
    return ToolResult(
        output=output,
        verified=False,
        verification_method="dns_unavailable",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "DNS_BINARY_CANDIDATES",
    "DNS_RECORD_TYPES",
    "dns_query_definition",
    "dns_query_handler",
    "validate_dns_name",
    "validate_record_type",
]
