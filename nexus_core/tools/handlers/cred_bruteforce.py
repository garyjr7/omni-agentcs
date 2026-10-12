"""Durable ``nexus.cred.bruteforce`` handler: credential testing with hydra.

This is the credential link of the chain: it takes a **username** and a
**wordlist** (typically harvested from a previous recon step) and tests them
against a service, returning any validated credential. It is deliberately
generic — nothing about a specific target or room is hardcoded; the planner
decides when to call it and with which inputs.

Safety rails:

* the wordlist must live inside the workspace (path traversal is rejected);
* attempts are capped by truncating the list to ``max_attempts`` lines;
* hydra runs ``-f`` (stop at the first hit) and ``-I`` (ignore restore files),
  with a fixed low task count to be gentle on services;
* ``MEDIUM`` risk, scope-gated on ``target`` and executed through the sandbox.
"""

from __future__ import annotations

import os
import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

CRED_ALLOWED_PROGRAMS = (*RECON_ALLOWED_PROGRAMS, "hydra")

CRED_SERVICES = ("ssh", "ftp")
CRED_DEFAULT_PORTS = {"ssh": 22, "ftp": 21}
CRED_DEFAULT_TIMEOUT_SECONDS = 300
CRED_MAX_TIMEOUT_SECONDS = 900
CRED_DEFAULT_MAX_ATTEMPTS = 200
CRED_MAX_ATTEMPTS = 5000
#: Concurrent hydra tasks. Kept low to avoid tripping service rate limits.
CRED_TASKS = 4

#: Successful hydra line, e.g.
#: ``[22][ssh] host: 1.2.3.4   misc: (null)   login: lin   password: p``.
#: Hydra may inject extra fields (``misc``) between host and login, so the
#: match tolerates arbitrary fields in between.
_FOUND_RE = re.compile(
    r"host:\s*(?P<host>\S+).*?login:\s*(?P<user>\S+)\s+password:\s*(?P<password>\S+)"
)


def cred_bruteforce_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.cred.bruteforce``."""
    return ToolDefinition(
        tool_id="nexus.cred.bruteforce",
        effect="credential_access",
        name="Credential testing",
        tenant_id=tenant_id,
        description=(
            "Prueba un usuario contra una wordlist en un servicio (ssh/ftp) y "
            "devuelve la credencial válida. Wordlist confinada al workspace."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "service": {"type": "string", "enum": list(CRED_SERVICES)},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password_file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "max_attempts": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": CRED_MAX_ATTEMPTS,
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
            },
            "required": ["target", "service", "username", "password_file"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.cred.bruteforce"],
        timeout_seconds=900,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _resolve_in_workspace(workspace_root: str, relative: str) -> str:
    """Resolve ``relative`` under ``workspace_root`` or raise ``ValueError``."""
    root = os.path.realpath(workspace_root)
    candidate = os.path.realpath(os.path.join(root, relative))
    if candidate != root and not candidate.startswith(root + os.sep):
        raise ValueError("password_file escapes the workspace")
    if not os.path.isfile(candidate):
        raise ValueError("password_file does not exist in the workspace")
    return candidate


def _truncate_wordlist(source: str, dest: str, max_attempts: int) -> int:
    """Copy at most ``max_attempts`` non-empty lines into ``dest``; return count."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    count = 0
    with open(source, encoding="utf-8", errors="replace") as reader, open(
        dest, "w", encoding="utf-8"
    ) as writer:
        for line in reader:
            token = line.rstrip("\r\n")
            if not token:
                continue
            writer.write(token + "\n")
            count += 1
            if count >= max_attempts:
                break
    return count


def parse_hydra_credentials(text: str) -> list[dict[str, str]]:
    """Extract validated credentials from hydra's output (stdout/stderr/file)."""
    found: list[dict[str, str]] = []
    for match in _FOUND_RE.finditer(text or ""):
        credential = {
            "host": match.group("host"),
            "username": match.group("user"),
            "password": match.group("password"),
        }
        if credential not in found:
            found.append(credential)
    return found


async def cred_bruteforce_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Test a username/wordlist against a service through the sandbox."""
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    service = str(arguments.get("service") or "").strip().lower()
    if service not in CRED_SERVICES:
        raise ValueError(f"unsupported service: {service!r}")
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password_file = _validate_text(
        arguments.get("password_file"), "password_file", max_length=1024
    )

    port = int(arguments.get("port") or CRED_DEFAULT_PORTS[service])
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    max_attempts = min(
        CRED_MAX_ATTEMPTS, max(1, int(arguments.get("max_attempts") or CRED_DEFAULT_MAX_ATTEMPTS))
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        CRED_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else CRED_DEFAULT_TIMEOUT_SECONDS),
    )

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    source_path = _resolve_in_workspace(workspace_root, password_file)
    run_dir = os.path.join(workspace_root, f"cred_{safe_run_id(context)}")
    wordlist_path = os.path.join(run_dir, "wordlist.txt")
    outfile_path = os.path.join(run_dir, "hydra.txt")
    attempts = _truncate_wordlist(source_path, wordlist_path, max_attempts)
    if attempts == 0:
        raise ValueError("password_file has no usable entries")

    argv = [
        "hydra",
        "-l",
        username,
        "-P",
        wordlist_path,
        "-s",
        str(port),
        "-t",
        str(CRED_TASKS),
        "-f",
        "-I",
        "-o",
        outfile_path,
        f"{service}://{target}",
    ]
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=CRED_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_HYDRA_IMAGE",
        default_image="kalilinux/kali-rolling",
    )

    combined = "\n".join([result.stdout or "", result.stderr or ""])
    credentials = parse_hydra_credentials(combined)
    if not credentials and os.path.isfile(outfile_path):
        try:
            with open(outfile_path, encoding="utf-8", errors="replace") as handle:
                credentials = parse_hydra_credentials(handle.read())
        except OSError:
            credentials = []

    evidence: dict[str, Any] = {
        "service": service,
        "port": port,
        "username": username,
        "attempts": attempts,
        "max_attempts": max_attempts,
        "found_count": len(credentials),
        "noise_level": "medium",
        "timeout_seconds": timeout_seconds,
    }

    if result.timed_out:
        return ToolResult(
            output={"error": "credential testing timed out", "target": target, "service": service},
            verified=False,
            verification_method="cred_bruteforce_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    verified = result.exit_code == 0
    return ToolResult(
        output={
            "target": target,
            "service": service,
            "port": port,
            "username": username,
            "attempts": attempts,
            "valid_credentials": credentials,
        },
        verified=verified,
        verification_method="cred_bruteforce_completed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
