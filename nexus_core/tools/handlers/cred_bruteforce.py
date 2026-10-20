"""Durable ``nexus.cred.bruteforce`` handler: credential testing with hydra.

This is the credential link of the chain: it takes a **username** and a
**wordlist** (typically harvested from a previous recon step) and tests them
against a service, returning any validated credential. It is deliberately
generic — nothing about a specific target or room is hardcoded; the planner
decides when to call it and with which inputs.

Safety rails:

* the wordlist must live inside the workspace or inside a standard read-only
  wordlist root (``/usr/share/wordlists``, ``/usr/share/seclists``,
  ``/opt/seclists``; extend with ``NEXUS_WORDLIST_ROOTS``). Anything else is
  rejected as path traversal;
* attempts are capped by truncating the list to ``max_attempts`` lines;
* hydra runs ``-f`` (stop at the first hit) and ``-I`` (ignore restore files),
  with a fixed low task count to be gentle on services;
* ``MEDIUM`` risk, scope-gated on ``target`` and executed through the sandbox.
* A validated password is **never returned**: it goes into the secret vault and
  the result carries ``secret_ref`` (V1-29). hydra prints the plaintext on stdout,
  so the returned capture is scrubbed too; the durable copy is the handler's own
  ``hydra.txt``, and the reusable one is the ``vault:<uuid>`` handle.
"""

from __future__ import annotations

import os
import tempfile
import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.kernel.secret_store import DEFAULT_SECRET_KIND, default_secret_store

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

CRED_ALLOWED_PROGRAMS = (*RECON_ALLOWED_PROGRAMS, "hydra")

CRED_SERVICES = ("ssh", "ftp", "telnet", "tcp")
CRED_DEFAULT_PORTS = {"ssh": 22, "ftp": 21, "telnet": 23}
CRED_DEFAULT_TIMEOUT_SECONDS = 300
CRED_MAX_TIMEOUT_SECONDS = 900

#: Read-only roots a wordlist may also live in. The rail exists to stop path
#: traversal into arbitrary files, not to force every engagement to copy
#: rockyou into its workspace: measured in run_1052d63f9bba4838902b3aa21bd27d21
#: (2026-10-19), where ``/usr/share/wordlists/rockyou.txt`` was rejected twice
#: and the credential branch -the only one left once the SQLi was closed- died
#: there. ``NEXUS_WORDLIST_ROOTS`` (``os.pathsep``-separated) extends the list.
WORDLIST_ROOTS_ENV = "NEXUS_WORDLIST_ROOTS"
DEFAULT_WORDLIST_ROOTS = ("/usr/share/wordlists", "/usr/share/seclists", "/opt/seclists")
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
            "devuelve la credencial válida. La wordlist debe estar en el "
            "workspace del engagement o en una ruta estándar "
            "(/usr/share/wordlists, /usr/share/seclists)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "service": {"type": "string", "enum": list(CRED_SERVICES)},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password_prompt": {"type": "string", "minLength": 1, "maxLength": 128},
                "login_prompt": {"type": "string", "minLength": 1, "maxLength": 128},
                "success_marker": {"type": "string", "minLength": 1, "maxLength": 128},
                "password_file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "max_attempts": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": CRED_MAX_ATTEMPTS,
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
            },
            # ``username`` is required by the ssh/ftp branch at runtime, and the
            # schema is the contract the model reads: reject it there instead of
            # spending a turn on ``username is required`` (measured twice in
            # run_7661dda481784eebb17a76e037c5722b).
            "allOf": [
                {
                    "if": {"properties": {"service": {"enum": ["ssh", "ftp"]}}},
                    "then": {"required": ["username"]},
                }
            ],
            "required": ["target", "service", "password_file"],
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


def _wordlist_roots(workspace_root: str) -> list[str]:
    """Roots a wordlist may be read from: the workspace plus the system ones."""
    roots = [os.path.realpath(workspace_root)]
    configured = [
        item.strip()
        for item in os.getenv(WORDLIST_ROOTS_ENV, "").split(os.pathsep)
        if item.strip()
    ]
    for root in configured or DEFAULT_WORDLIST_ROOTS:
        resolved = os.path.realpath(root)
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _resolve_wordlist(workspace_root: str, source: str) -> str:
    """Resolve ``source`` under an allowed wordlist root or raise ``ValueError``.

    An absolute path is accepted only when it resolves inside an allowed root; a
    relative one is looked up in the workspace first and then in the system
    roots, so ``rockyou.txt`` finds ``/usr/share/wordlists/rockyou.txt`` without
    the model having to guess where the operator installed it.
    """
    text = str(source).strip()
    roots = _wordlist_roots(workspace_root)
    candidates = [
        os.path.realpath(text if os.path.isabs(text) else os.path.join(roots[0], text))
    ]
    if not os.path.isabs(text):
        candidates.extend(os.path.realpath(os.path.join(root, text)) for root in roots[1:])
    for candidate in candidates:
        if not any(candidate == root or candidate.startswith(root + os.sep) for root in roots):
            continue
        if os.path.isfile(candidate):
            return candidate
    raise ValueError(
        "password_file must be inside the engagement workspace or a standard "
        f"wordlist root ({', '.join(DEFAULT_WORDLIST_ROOTS)}); extend with "
        f"{WORDLIST_ROOTS_ENV}"
    )


def _truncate_wordlist(source: str, dest: str, max_attempts: int) -> int:
    """Copy at most ``max_attempts`` non-empty lines into ``dest``; return count.

    The list is streamed and cut at ``max_attempts``, so its total size is
    irrelevant to the work done: the old 16 MB ceiling only rejected the one
    list an operator always has. Measured in
    ``run_7661dda481784eebb17a76e037c5722b`` (2026-10-20): ``rockyou.txt``
    (134 MB) was refused with "wordlist exceeds 16 MB", the model could not
    slice it into a usable path either (the write into ``/usr/share/wordlists``
    was denied), and the credential branch died with the hash already in hand.
    """
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    count = 0
    with open(source, encoding="utf-8", errors="replace") as reader, open(
        dest, "w", encoding="utf-8"
    ) as writer:
        while line := reader.readline(4097):
            if len(line) > 4096:
                raise ValueError("wordlist entry exceeds 4096 characters")
            token = line.rstrip("\r\n")
            if not token:
                continue
            writer.write(token + "\n")
            count += 1
            if count >= max_attempts:
                break
    return count


def store_discovered_credentials(
    credentials: list[dict[str, Any]],
    *,
    tenant_id: str = "system",
    kind: str = DEFAULT_SECRET_KIND,
) -> list[dict[str, str]]:
    """Replace every plaintext password with its ``secret_ref`` (V1-29).

    The plaintext is written once into the vault; what travels onward (result,
    evidence, blackboard, prompt) is the reference. A credential without a
    password (an access-token flow) keeps its fields untouched.
    """
    stored: list[dict[str, str]] = []
    vault = default_secret_store()
    for credential in credentials or ():
        entry = {str(key): str(value) for key, value in credential.items()}
        password = entry.pop("password", "")
        if password:
            entry["secret_ref"] = vault.put(
                password.encode("utf-8"), kind=kind, tenant_id=tenant_id
            )
        stored.append(entry)
    return stored


def _scrub_plaintext(text: str, credentials: list[dict[str, Any]]) -> str:
    """Remove the validated passwords from a raw capture before returning it."""
    cleaned = text or ""
    for credential in credentials or ():
        password = str((credential or {}).get("password") or "")
        if password:
            cleaned = cleaned.replace(password, "[REDACTED]")
    return cleaned


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


async def cred_bruteforce_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Test a username/wordlist against a service through the sandbox."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, cred_bruteforce_definition().input_schema)
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    service = str(arguments.get("service") or "").strip().lower()
    if service not in CRED_SERVICES:
        raise ValueError(f"unsupported service: {service!r}")
    username = (_validate_text(arguments.get("username"), "username", max_length=128)
                if service in {"ssh", "ftp"} or arguments.get("username") else "")
    password_file = _validate_text(
        arguments.get("password_file"), "password_file", max_length=1024
    )

    port = int(arguments.get("port") or CRED_DEFAULT_PORTS.get(service, 0))
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
    source_path = _resolve_wordlist(workspace_root, password_file)
    run_dir = tempfile.mkdtemp(prefix=f"cred_{safe_run_id(context)}_", dir=workspace_root)
    wordlist_path = os.path.join(run_dir, "wordlist.txt")
    outfile_path = os.path.join(run_dir, "hydra.txt")
    attempts = _truncate_wordlist(source_path, wordlist_path, max_attempts)
    if attempts == 0:
        raise ValueError("password_file has no usable entries")

    if service in {"tcp", "telnet"}:
        from ._tcp_credentials import TCP_CREDENTIAL_SCRIPT
        from .http_request import _parse_last_json
        if not 1 <= port <= 65535:
            raise ValueError("TCP requires an explicit valid port")
        success = _validate_text(arguments.get("success_marker"), "success_marker", max_length=128)
        password_prompt = _validate_text(arguments.get("password_prompt", "Password:"), "password_prompt", max_length=128)
        login_prompt = str(arguments.get("login_prompt") or "")
        if login_prompt and not username:
            raise ValueError("login_prompt requires username")
        sandbox = sandbox_for_environment(workspace_root, allowed_programs=CRED_ALLOWED_PROGRAMS)
        result = await run_in_sandbox(
            sandbox, ["python3", "-c", TCP_CREDENTIAL_SCRIPT, target, str(port), username,
                      wordlist_path, password_prompt, success, login_prompt,
                      "1" if service == "telnet" else "0"],
            timeout_seconds=timeout_seconds, image_env="NEXUS_HTTP_IMAGE",
            default_image="python:3.12-alpine",
        )
        payload = _parse_last_json(result.stdout) if result.stdout else {}
        stored = store_discovered_credentials(
            payload.get("valid_credentials") or [], tenant_id=context.tenant_id
        )
        output = {key: value for key, value in payload.items() if key != "valid_credentials"}
        output.update({"target": target, "service": service, "port": port,
                       "valid_credentials": stored})
        return ToolResult(
            output=output,
            verified=(result.exit_code == 0 and not result.timed_out and bool(payload)
                      and (bool(payload.get("valid_credentials")) or payload.get("errors") == 0)),
            exit_code=result.exit_code, timed_out=result.timed_out,
            verification_method="tcp_positive_marker",
            evidence={"max_attempts": max_attempts,
                      "secret_refs": [entry["secret_ref"] for entry in stored
                                      if entry.get("secret_ref")]},
            stdout=_scrub_plaintext(result.stdout or "", payload.get("valid_credentials") or []),
            stderr=_scrub_plaintext(result.stderr or "", payload.get("valid_credentials") or []),
        )

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
                credentials = parse_hydra_credentials(handle.read(1_000_000))
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

    # V1-29: the plaintext is stored, never forwarded. What the loop, the
    # blackboard and the prompt see is the handle.
    stored = store_discovered_credentials(credentials, tenant_id=context.tenant_id)
    evidence["secret_refs"] = [entry["secret_ref"] for entry in stored if entry.get("secret_ref")]
    stdout = _scrub_plaintext(result.stdout or "", credentials)
    stderr = _scrub_plaintext(result.stderr or "", credentials)

    if result.timed_out:
        return ToolResult(
            output={"error": "credential testing timed out", "target": target, "service": service},
            verified=False,
            verification_method="cred_bruteforce_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=stdout,
            stderr=stderr,
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
            "valid_credentials": stored,
        },
        verified=verified,
        verification_method="cred_bruteforce_completed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=stdout,
        stderr=stderr,
    )
