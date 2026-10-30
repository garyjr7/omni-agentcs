"""Durable ``nexus.attack.ad_user_enum`` handler (LOW risk).

The missing step between "this page published ``j.doe@services.local`` and a
staff list" and "this account exists". Before it, the engine had exactly one
producer of ``user`` facts (``wp_enum``): a name derived from a page could be
suggested to the model and never verified, so a run either sprayed a guess or
dropped the lead.

Two oracles, neither of which sends a password, so **neither can lock an
account**:

* ``kerbrute userenum`` when installed. It prints a verdict per account, so
  existence *and* absence are proved (``attribution=full``).
* ``impacket-GetNPUsers -no-pass -usersfile`` otherwise. It proves the accounts
  it names (an AS-REP hash, or "doesn't have UF_DONT_REQUIRE_PREAUTH set") and
  leaves the rest ``unknown`` -the shipped Impacket only logs
  ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` without the username, so absence cannot be
  attributed (``attribution=partial``).

That asymmetry is the point of the module: a tool that turned "not mentioned"
into "does not exist" would validate a fabricated list and close a branch that
was never probed. The output says which oracle answered and what it proved.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.impacket_asrep import (
    MODE_ASREP,
    MODE_KERBRUTE,
    parse_user_enum,
)

from ._ad import ad_sandbox, resolve_ad_binary, validate_domain, validate_host, validate_username
from ._exec import run_in_sandbox, safe_run_id
from ._impacket_resolver import resolve_impacket_binary

USER_ENUM_MAX_USERS = 500
USER_ENUM_DEFAULT_TIMEOUT_SECONDS = 300
USER_ENUM_MAX_TIMEOUT_SECONDS = 900


def user_enum_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for the Kerberos user enumeration."""
    return ToolDefinition(
        tool_id="nexus.attack.ad_user_enum",
        name="Enumeración de usuarios AD (Kerberos, sin contraseña)",
        tenant_id=tenant_id,
        description=(
            "Confirma qué cuentas existen en un dominio sin enviar ninguna "
            "contraseña (kerbrute userenum; si no está, GetNPUsers -no-pass): "
            "no bloquea cuentas. Devuelve existentes, inexistentes (solo con "
            "kerbrute) y sin veredicto, además de las cuentas sin preautenticación "
            "con su hash AS-REP. Pasa aquí los candidatos derivados de una página "
            "antes de probar contraseñas; el DC va en dc_ip."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string", "minLength": 1, "maxLength": 255},
                "domain": {"type": "string", "minLength": 1, "maxLength": 255},
                "users": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                    "minItems": 1,
                    "maxItems": USER_ENUM_MAX_USERS,
                    "description": (
                        "Lista de nombres a probar (no vacía). Esta tool "
                        "necesita un DC con Kerberos y nombres ya obtenidos; si "
                        "el host no es un controlador de dominio o aún no tienes "
                        "usuarios, no la uses: enumera primero el servicio "
                        "(nexus.recon.smb, nexus.recon.ftp, la web)."
                    ),
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": USER_ENUM_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["dc_ip", "domain", "users"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        effect="recon",
        required_permissions=["execute:tool:nexus.attack.ad_user_enum"],
        timeout_seconds=USER_ENUM_MAX_TIMEOUT_SECONDS,
        max_output_bytes=4_000_000,
        scope_target_field="dc_ip",
        scope_required=True,
    )


def _normalize_users(values: object) -> list[str]:
    """Validate, de-duplicate and bound the account list (order preserved)."""
    if isinstance(values, (str, bytes, dict)) or not isinstance(values, Iterable):
        raise ValueError("users must be a collection of usernames")
    users: list[str] = []
    seen: set[str] = set()
    for value in values:
        name = validate_username(value, field="users")
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        users.append(name)
    if not users:
        raise ValueError("at least one username is required")
    if len(users) > USER_ENUM_MAX_USERS:
        raise ValueError(f"too many users: {len(users)} > {USER_ENUM_MAX_USERS}")
    return users


def _next_steps(result: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    roastable = result.get("roastable") or []
    if roastable:
        steps.append(
            "cuentas sin preautenticación: "
            + ", ".join(str(item.get("username")) for item in roastable[:5])
            + "; lleva su hash a nexus.post.crack_hash con hash_type=krb5asrep"
        )
    unknown = result.get("unknown") or []
    if unknown and result.get("attribution") == "partial":
        steps.append(
            f"{len(unknown)} cuenta(s) sin veredicto: este oráculo no puede probar "
            "ausencia; instala kerbrute (o valida solo las que piensas usar) antes "
            "de considerarlas inexistentes"
        )
    if result.get("existing"):
        steps.append(
            "con las cuentas confirmadas, enumera SPN/acceso con credenciales o "
            "prueba 1 contraseña por cuenta (política de bloqueo del dominio)"
        )
    return steps


async def ad_user_enum_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Run the unauthenticated user enumeration through the sandbox."""
    dc_ip = validate_host(arguments.get("dc_ip"), field="dc_ip")
    domain = validate_domain(arguments.get("domain"))
    users = _normalize_users(arguments.get("users"))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        USER_ENUM_MAX_TIMEOUT_SECONDS,
        max(
            30,
            int(requested_timeout)
            if requested_timeout
            else USER_ENUM_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    kerbrute = resolve_ad_binary("kerbrute")
    get_np_users = resolve_impacket_binary("GetNPUsers")
    binary = kerbrute or get_np_users
    if not binary:
        return ToolResult(
            output={
                "error": "no user-enumeration binary available",
                "guidance": (
                    "Instala kerbrute (veredicto por cuenta) o impacket "
                    "(`sudo apt install python3-impacket`), que ya viene con "
                    "GetNPUsers."
                ),
                "users": users,
            },
            verified=False,
            outcome="unavailable",
            verification_method="userenum_unavailable",
        )
    mode = MODE_KERBRUTE if kerbrute else MODE_ASREP

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    users_path = Path(workspace_root).resolve() / f"userenum_users_{safe_run_id(context)}.txt"
    try:
        users_path.write_text("\n".join(users) + "\n", encoding="utf-8")
        os.chmod(users_path, 0o600)
    except OSError as exc:
        return ToolResult(
            output={"error": f"cannot stage the user list: {exc}"},
            verified=False,
            outcome="unavailable",
            verification_method="userenum_staging_failed",
        )

    if mode == MODE_KERBRUTE:
        argv = [
            binary,
            "userenum",
            "--dc",
            dc_ip,
            "-d",
            domain,
            str(users_path),
        ]
    else:
        # GetNPUsers takes ``domain/`` (empty user) plus ``-usersfile``; the john
        # format is the one ``crack_hash`` consumes later.
        argv = [
            binary,
            f"{domain}/",
            "-dc-ip",
            dc_ip,
            "-no-pass",
            "-usersfile",
            str(users_path),
            "-format",
            "john",
        ]

    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )

    evidence: dict[str, Any] = {
        "dc_ip": dc_ip,
        "domain": domain,
        "mode": mode,
        "requested": len(users),
        "timeout_seconds": timeout_seconds,
        # No password is sent and no failed logon is produced: the oracle cannot
        # lock an account. Stated as evidence so a later review does not have to
        # infer it from the tool name.
        "lockout_risk": "none",
        "noise_level": "low",
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "user enumeration timed out", "dc_ip": dc_ip, "users": users},
            verified=False,
            verification_method="userenum_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    text = f"{result.stdout}\n{result.stderr}"
    parsed = parse_user_enum(text, users, mode=mode, domain=domain)
    payload = parsed.to_dict()
    evidence.update(
        {
            "attribution": parsed.attribution,
            "existing_count": len(parsed.existing),
            "missing_count": len(parsed.missing),
            "unknown_count": len(parsed.unknown),
            "roastable_count": len(parsed.roastable),
            "raw_sha256": parsed.raw_sha256,
        }
    )
    answered = bool(parsed.existing or parsed.missing or parsed.roastable)
    output: dict[str, Any] = {
        "dc_ip": dc_ip,
        "domain": domain,
        "users_requested": len(users),
        **payload,
        "next_steps": _next_steps(payload),
    }
    if not answered:
        # The tool ran and named nobody: that is not "no accounts exist", it is
        # "no answer". Keep it out of the board and say why.
        evidence["reason"] = "the binary printed no verdict for any requested account"
        return ToolResult(
            output=output,
            verified=False,
            outcome="negative",
            verification_method="userenum_no_answer",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    return ToolResult(
        output=output,
        verified=result.exit_code == 0,
        verification_method=f"userenum_{mode}_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
