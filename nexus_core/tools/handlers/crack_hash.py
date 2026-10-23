"""Durable ``nexus.post.crack_hash``: crack a hash (or a key passphrase) offline.

The missing link between *holding* a hash and *using* it: Brute It v6/v7 walked
away from a panel with an encrypted RSA key and no tool to open it, and Simple
CTF's CMS hash was extracted fifteen times in fifty turns without ever being
cracked. This handler is offline by design -the target is never contacted- so it
needs no scope target, only the material and a wordlist.

What it accepts:

* a hash line (``user:hash`` or a bare ``$6$...``), with ``hash_type`` either
  explicit or autodetected from the shape;
* a PEM/OpenSSH private key, which is converted with ``ssh2john`` first -that is
  exactly the artifact an exposed panel hands out, and ``john --format=ssh`` is
  the file the passphrase lives in.

What it returns is a **reference**, never the plaintext (V1-29): the cracked
password goes into the vault and the result carries ``valid_credentials`` with
``secret_ref``, so ``nexus.post.ssh_exec``/``nexus.web.request`` can consume it
without the secret entering the model's context. Only ``john --show`` promotes a
hit: the cracking run's own output is not evidence of a password.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import run_in_sandbox, safe_run_id
from .cred_bruteforce import store_discovered_credentials
from .workspace import resolve_workspace_path, workspace_root

#: The client script is stdlib + john: the sandbox allowlist only has to admit
#: ``python3`` (same pattern as the HTTP/pivot clients). Absolute candidates are
#: tried because ``john`` lives in ``/usr/sbin`` on Kali and the sandbox PATH is
#: the minimal ``/usr/local/bin:/usr/bin:/bin``.
CRACK_ALLOWED_PROGRAMS: tuple[str, ...] = ("python3",)

CRACK_TOOL_TIMEOUT_SECONDS = 900
CRACK_DEFAULT_TIMEOUT_SECONDS = 600

#: Our vocabulary → ``john --format``. ``auto`` is resolved by shape before this
#: table is consulted.
CRACK_FORMATS = {
    "md5": "raw-md5",
    "sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "sha512": "raw-sha512",
    "ntlm": "nt",
    "bcrypt": "bcrypt",
    "md5crypt": "md5crypt",
    "sha256crypt": "sha256crypt",
    "sha512crypt": "sha512crypt",
    "yescrypt": "yescrypt",
    "argon2": "argon2",
    "ssh": "ssh",
    # B1: a Kerberos hash keeps its own format. ``krb5asrep`` is what
    # ``GetNPUsers -format john`` prints (no preauthentication) and ``krb5tgs``
    # is the service ticket a Kerberoast returns; ``john`` has a format for each.
    "krb5asrep": "krb5asrep",
    "krb5tgs": "krb5tgs",
}

#: What the model may name explicitly. The enum used to be a short list
#: (auto/md5/sha1/sha256/bcrypt/ssh) while the table above supported the
#: crypt(3) family, so the schema rejected ``sha512crypt`` with "is not one of"
#: in run P4 of DeadDrop (2026-10-22) right after the handler had listed it as
#: valid. An enum the handler cannot honour is a wall.
CRACK_CHOICES = ("auto", *CRACK_FORMATS)

#: Shapes john can name without help. Order matters: a crypt(3) prefix wins over
#: a length, because ``$1$…`` is not a 34-character raw hash.
_CRYPT_PREFIXES = (
    ("$2a$", "bcrypt"),
    ("$2b$", "bcrypt"),
    ("$2y$", "bcrypt"),
    ("$1$", "md5crypt"),
    ("$5$", "sha256crypt"),
    ("$6$", "sha512crypt"),
    ("$y$", "yescrypt"),
    ("$argon2", "argon2"),
)
_HEX_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
#: Kerberos hash lines carry ``:`` inside (``user@realm:hash``), so they must be
#: read whole and never split as a shadow-style line.
_KERBEROS_PREFIXES = ("$krb5asrep$", "$krb5tgs$")
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
#: The key itself, out of whatever page carried it: an exposed panel prints it
#: inside ``<pre>``/``<textarea>``, and ``ssh2john`` only accepts the armour.
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _pem_block(text: str) -> str:
    """The first private-key block in ``text``, or ``""`` when there is none."""
    match = _PEM_BLOCK_RE.search(text)
    return match.group(0).strip() if match else ""

#: Client script. argv after ``-c``: workdir hash_path format wordlist ssh_path
#: timeout_seconds label. ``ssh_path`` is the *key* file when one must be
#: converted, else the empty string; ``label`` renames the ``ssh2john`` line so
#: the hit is attributed to the SSH user and not to the key's temp path.
CRACK_CLIENT_SCRIPT = r'''
import json, os, shutil, subprocess, sys

def emit(payload):
    print(json.dumps(payload))

def resolve(name, absolute):
    for candidate in absolute:
        if os.path.sep in candidate and os.path.exists(candidate):
            return candidate
    found = shutil.which(name)
    if found:
        return found
    for candidate in absolute:
        if os.path.exists(candidate):
            return candidate
    return None

def run(argv, timeout):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)

def main():
    workdir, hash_path, fmt, wordlist, ssh_path, timeout, label = sys.argv[1:8]
    limit = float(timeout)
    john = resolve("john", ["/usr/sbin/john", "/usr/bin/john", "/opt/john/run/john"])
    if john is None:
        emit({"ok": False, "error": "john_unavailable"})
        return
    target = hash_path
    john_dir = os.path.dirname(john)
    if ssh_path:
        converter = resolve("ssh2john", [
            "/usr/share/john/ssh2john.py", "/usr/bin/ssh2john",
            os.path.join(john_dir, "ssh2john.py"),
        ])
        if converter is None:
            emit({"ok": False, "error": "ssh2john_unavailable"})
            return
        argv = ([sys.executable, converter, ssh_path] if converter.endswith(".py")
                else [converter, ssh_path])
        converted = run(argv, 60)
        text = (converted.stdout or "").strip()
        if not text:
            emit({"ok": False, "error": "ssh2john_failed",
                  "detail": (converted.stderr or "")[:300]})
            return
        # ``ssh2john`` labels every line with the key's path; the credential
        # belongs to the SSH user, so keep the hash and replace the label.
        if label and ":" in text:
            text = label + ":" + text.split(":", 1)[1]
        ssh_hash = os.path.join(workdir, "ssh.hash")
        with open(ssh_hash, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        target = ssh_hash
        fmt = fmt or "ssh"
    pot = os.path.join(workdir, "john.pot")
    base = [john, "--pot=" + pot, "--session=" + os.path.join(workdir, "john"),
            "--wordlist=" + wordlist]
    if fmt:
        base.append("--format=" + fmt)
    cracked = run(base + [target], limit)
    show = run([john, "--show", "--pot=" + pot]
               + (["--format=" + fmt] if fmt else []) + [target], 60)
    found = []
    for line in (show.stdout or "").splitlines():
        line = line.strip()
        if not line or ":" not in line or "password hash" in line.lower():
            continue
        label, _, rest = line.partition(":")
        password = rest.split(":", 1)[0] if ":" in rest else rest
        if not label or not password:
            continue
        found.append({"label": label, "password": password})
    tail = "\n".join(((cracked.stdout or "") + (cracked.stderr or "")).splitlines()[-6:])
    emit({
        "ok": True,
        "cracked": found,
        "john_exit": cracked.returncode,
        "john_timed_out": cracked.returncode == 124,
        "john_tail": tail[-600:],
        "format": fmt or "",
        "show": (show.stdout or "")[-600:],
    })

try:
    main()
except subprocess.TimeoutExpired:
    emit({"ok": False, "error": "john_timeout"})
except Exception as exc:
    emit({"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:300]})
'''


def _hash_field(material: str) -> str:
    """The hash itself, out of whatever line carried it.

    A ``/etc/shadow`` line is ``user:$6$…:19700:0:99999:7:::``: the hash is the
    field after the user, and the trailing ageing fields are not part of it.
    Pasting the whole line is what the model does when a file preview leaks one
    (DeadDrop P4, 2026-10-22: autodetection failed on ``svc-drop:$6$…:19700``),
    so the field is extracted before the shape is read.
    """
    text = material.strip()
    if text.startswith(_KERBEROS_PREFIXES):
        return text
    if text.startswith(tuple(prefix for prefix, _ in _CRYPT_PREFIXES)):
        return text
    for field in text.split(":"):
        candidate = field.strip()
        if candidate.startswith(tuple(prefix for prefix, _ in _CRYPT_PREFIXES)):
            return candidate
    return text


def detect_hash_type(material: str) -> str:
    """Name the hash by its shape, or ``""`` when it is not recognisable.

    Only unambiguous shapes are named: a wrong format makes ``john`` answer
    ``No password hashes loaded`` and the run would read it as "not cracked".
    """
    text = _hash_field(material)
    if _PEM_RE.search(material):
        return "ssh"
    if text.startswith(_KERBEROS_PREFIXES):
        return "krb5asrep" if text.startswith("$krb5asrep$") else "krb5tgs"
    for prefix, name in _CRYPT_PREFIXES:
        if text.startswith(prefix):
            return name
    candidate = text.split(":", 1)[1] if ":" in text else text
    candidate = candidate.strip()
    if re.fullmatch(r"[a-fA-F0-9]+", candidate):
        return _HEX_LENGTHS.get(len(candidate), "")
    return ""


def crack_hash_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.crack_hash``."""
    return ToolDefinition(
        tool_id="nexus.post.crack_hash",
        effect="credential_access",
        name="Offline hash cracking",
        tenant_id=tenant_id,
        description=(
            "Rompe offline un hash o la passphrase de una clave privada con john "
            "(wordlist). Acepta `hash_content` (hash o PEM) o `hash_file` del "
            "workspace; autodetecta el tipo. Devuelve la credencial como "
            "`secret_ref` del vault, no en claro."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hash_content": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 65536,
                    "description": (
                        "El hash ('user:$6$...' o '$6$...') o el contenido PEM de "
                        "una clave privada."
                    ),
                },
                "hash_file": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1024,
                    "description": (
                        "Ruta dentro del workspace del fichero con el hash o con "
                        "la clave privada (alternativa a `hash_content`)."
                    ),
                },
                "hash_type": {
                    "type": "string",
                    "enum": list(CRACK_CHOICES),
                    "default": "auto",
                    "description": (
                        "Tipo de hash; `auto` lo deduce de la forma ($6$ = "
                        "sha512crypt, PEM = clave SSH, 32 hex = md5…)."
                    ),
                },
                "username": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "description": (
                        "Usuario al que pertenece el secreto (p. ej. `john`), para "
                        "que el hecho quede ligado a él."
                    ),
                },
                "target": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": "Host del que salió el hash (opcional).",
                },
                "wordlist": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1024,
                    "description": (
                        "Wordlist (workspace o ruta estándar). Por defecto "
                        "rockyou.txt si está instalada."
                    ),
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": CRACK_TOOL_TIMEOUT_SECONDS,
                },
            },
            "anyOf": [{"required": ["hash_content"]}, {"required": ["hash_file"]}],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.post.crack_hash"],
        timeout_seconds=CRACK_TOOL_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
    )


def _material(arguments: dict[str, Any], root: str) -> str:
    """The hash or key this call works on: inline content or a workspace file."""
    content = str(arguments.get("hash_content") or "")
    path = str(arguments.get("hash_file") or "").strip()
    if content and path:
        raise ValueError("pass either hash_content or hash_file, not both")
    if path:
        resolved = resolve_workspace_path(path, root=root)
        with open(resolved, encoding="utf-8", errors="replace") as handle:
            content = handle.read(65537)
        if len(content) > 65536:
            raise ValueError("hash_file is larger than 64 KiB")
    if not content.strip():
        raise ValueError("hash_content or hash_file is required")
    # A key copied from a panel arrives wrapped in HTML: keep only the armour so
    # ``ssh2john`` reads it as a key instead of as a config file.
    return _pem_block(content) or content.strip()


def _hash_path(material: str, username: str, workdir: str) -> str:
    """Write the labelled hash john expects (``user:hash`` or a bare hash).

    A label is what makes ``john --show`` printable: without it john prints the
    hash itself as the "user" and the password after it, which still parses, but
    the credential could not be attributed to ``username``.
    """
    text = material.strip()
    if _PEM_RE.search(text):
        path = os.path.join(workdir, "id_key")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        return path
    if ":" in text.split("$", 1)[0]:
        # Already ``user:hash``: keep the caller's own label.
        labelled = text
    elif username:
        labelled = f"{username}:{text}"
    else:
        labelled = text
    path = os.path.join(workdir, "hashes.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(labelled + "\n")
    return path


def _crack_wordlist(root: str, requested: Any) -> str:
    """Resolve the wordlist, defaulting to rockyou when it is installed."""
    from .cred_bruteforce import _resolve_wordlist

    if requested:
        return _resolve_wordlist(root, str(requested))
    for candidate in ("rockyou.txt", "/usr/share/wordlists/rockyou.txt"):
        try:
            return _resolve_wordlist(root, candidate)
        except Exception:  # noqa: BLE001 - try the next well-known name
            continue
    raise ValueError(
        "wordlist is required: rockyou.txt is not installed and none was passed"
    )


async def crack_hash_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Crack a hash or key passphrase through the sandbox and keep the secret."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, crack_hash_definition().input_schema)
    root = workspace_root()
    material = _material(arguments, root)
    requested_type = str(arguments.get("hash_type") or "auto").strip().lower()
    if requested_type == "auto":
        hash_type = detect_hash_type(material)
        if not hash_type:
            raise ValueError(
                "hash_type could not be autodetected: pass it explicitly "
                f"(one of {', '.join(sorted(CRACK_FORMATS))})"
            )
    elif requested_type in CRACK_FORMATS:
        hash_type = requested_type
    else:
        raise ValueError(f"unsupported hash_type: {requested_type!r}")
    fmt = CRACK_FORMATS[hash_type]
    username = str(arguments.get("username") or "").strip()
    target = str(arguments.get("target") or "").strip()
    wordlist = _crack_wordlist(root, arguments.get("wordlist"))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        CRACK_TOOL_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else CRACK_DEFAULT_TIMEOUT_SECONDS),
    )

    run_dir = tempfile.mkdtemp(prefix=f"crack_{safe_run_id(context)}_", dir=root)
    hash_path = _hash_path(material, username, run_dir)
    ssh_path = hash_path if hash_type == "ssh" else ""

    sandbox = sandbox_for_environment(root, allowed_programs=CRACK_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        ["python3", "-c", CRACK_CLIENT_SCRIPT, run_dir, hash_path, fmt, wordlist,
         ssh_path, str(max(10, timeout_seconds - 30)), username],
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_CRACK_IMAGE",
        default_image="kalilinux/kali-rolling",
    )
    from .http_request import _parse_last_json

    evidence: dict[str, Any] = {
        "hash_type": hash_type,
        "john_format": fmt,
        "username": username or None,
        "target": target or None,
        "wordlist": os.path.basename(wordlist),
        "timeout_seconds": timeout_seconds,
        "noise_level": "low",
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "hash cracking timed out", "hash_type": hash_type},
            verified=False,
            outcome="timeout",
            timed_out=True,
            verification_method="crack_hash_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    try:
        payload = _parse_last_json(result.stdout or "")
    except ValueError:
        payload = {}
    if not payload.get("ok"):
        error = str(payload.get("error") or "")
        detail = str(payload.get("detail") or "")
        if error in {"john_unavailable", "ssh2john_unavailable"}:
            return ToolResult(
                output={
                    "error": f"{error.split('_')[0]} is not available in the sandbox",
                    "message": (
                        "john (o ssh2john) no está instalado en el sandbox: el "
                        "hash no se llegó a probar. Instálalo con "
                        "nexus.system.install o rompe el hash fuera de la tool."
                    ),
                    "hash_type": hash_type,
                },
                verified=False,
                outcome="unavailable",
                verification_method="crack_hash_unavailable",
                evidence=evidence,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        return ToolResult(
            output={
                "error": error or "john did not return a result",
                "detail": detail or None,
                "hash_type": hash_type,
            },
            verified=False,
            verification_method="crack_hash_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    cracked = [entry for entry in payload.get("cracked") or () if entry.get("password")]
    credentials = [
        {
            "username": str(entry.get("label") or username or "hash"),
            "password": str(entry["password"]),
        }
        for entry in cracked
    ]
    stored = store_discovered_credentials(credentials, tenant_id=context.tenant_id)
    evidence.update(
        {
            "cracked_count": len(stored),
            "john_exit": payload.get("john_exit"),
            "john_verdict": payload.get("john_tail"),
            "secret_refs": [entry["secret_ref"] for entry in stored if entry.get("secret_ref")],
        }
    )
    # The cracked password is never echoed: it went to the vault, and the salt
    # / the hash itself are the only reusable identifiers here.
    output: dict[str, Any] = {
        "hash_type": hash_type,
        "john_format": payload.get("format") or fmt,
        "cracked_count": len(stored),
        "valid_credentials": stored,
        "wordlist": os.path.basename(wordlist),
    }
    if target:
        output["target"] = target
    if not stored:
        output["message"] = (
            "john terminó la wordlist sin romper el hash. Prueba otra wordlist, "
            "otro `hash_type` o confirma que el hash no está truncado."
        )
        output["john_verdict"] = payload.get("john_tail")
    return ToolResult(
        output=output,
        verified=bool(stored),
        outcome="" if stored else "negative",
        verification_method="crack_hash_john_show",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "CRACK_ALLOWED_PROGRAMS",
    "CRACK_CHOICES",
    "CRACK_CLIENT_SCRIPT",
    "CRACK_FORMATS",
    "crack_hash_definition",
    "crack_hash_handler",
    "detect_hash_type",
    "_pem_block",
]
