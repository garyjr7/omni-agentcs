"""Durable post-exploitation SSH handlers.

Once a credential is validated (``nexus.cred.bruteforce``), the chain continues
inside the host: ``nexus.post.ssh_exec`` runs a single command and
``nexus.post.enum_system`` collects the standard Linux privilege-escalation
surface (identity, users, ``sudo -l``, SUID files, capabilities, cron, listeners).
``nexus.post.ssh_upload`` places a workspace file on the host over SFTP, which is
the Linux counterpart of ``nexus.post.smb_upload`` and the primitive a privesc
step needs when the target has **no** outbound network (``curl`` to fetch a
PE-assist script times out, so the script has to be pushed from the operator).

Design notes:

* The SSH client is a stdlib-independent script run through the sandbox with
  ``python3`` + ``paramiko``; it fails closed (``ssh_unavailable``) when
  paramiko is missing instead of raising.
* ``ssh_exec`` is ``HIGH`` risk (remote command execution) and rejects a
  conservative destructive-command denylist; ``enum_system`` only runs a fixed
  allowlist of read-only commands (``MEDIUM``).
* ``ssh_upload`` writes one file, so it is ``MEDIUM`` (same class as
  ``nexus.post.smb_upload``), but its post-condition is strict: after the ``put``
  it **re-reads the remote file over SFTP and compares sha256 with the local
  source**, so a truncated or redirected upload is a declared negative
  (``ssh_upload_hash_mismatch``) instead of a silent success.
* Connections are short-lived (connect, run, disconnect); no credential is
  persisted by these handlers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox
from .workspace import resolve_workspace_path

SSH_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
SSH_DEFAULT_PORT = 22
SSH_DEFAULT_TIMEOUT_SECONDS = 120
#: Enumeration walks the filesystem over a possibly high-latency link.
ENUM_DEFAULT_TIMEOUT_SECONDS = 300
#: One SFTP put plus the read-back verification: the default command budget is
#: generous enough for a ~1 MB PE-assist script on a slow link.
UPLOAD_DEFAULT_TIMEOUT_SECONDS = 180
SSH_MAX_TIMEOUT_SECONDS = 600
SSH_ENUM_MARKER = "__SUDO__"

#: Octal file mode accepted by ``ssh_upload`` (``755``, ``0644``, ...).
SSH_FILE_MODE_RE = re.compile(r"^[0-7]{3,4}$")

#: Fixed, read-only enumeration commands. ``ssh_exec`` runs none of these.
ENUM_COMMANDS: dict[str, str] = {
    "identity": "id",
    "kernel": "uname -a",
    "os_release": "cat /etc/os-release 2>/dev/null",
    "users": "cat /etc/passwd",
    "home": "ls -la ~ 2>/dev/null",
    # Bounded filesystem walks: each is capped remotely so a slow link cannot
    # stall the whole enumeration.
    "suid": "timeout 30 find / -xdev -perm -4000 -type f 2>/dev/null",
    "capabilities": "timeout 20 getcap -r /usr/bin /usr/sbin /bin /sbin 2>/dev/null",
    "cron": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null",
    "listening": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    # Handled specially by the client: sudo -n -l, falling back to sudo -S -l.
    SSH_ENUM_MARKER: "sudo -n -l",
}

#: Conservative destructive-command denylist for ``ssh_exec`` (case-insensitive).
SSH_FORBIDDEN_TOKENS: tuple[str, ...] = (
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "mkfs",
    ":(){",
    "rm -rf /",
    "dd if=",
    "dd of=",
    "> /dev/sd",
    "iptables -f",
    "userdel",
    "passwd ",
    "chmod 777 /",
)

_SUDO_RULE_RE = re.compile(r"^\s*\((?P<who>[^)]*)\)\s+(?P<command>\S.*)$")

#: Client script. argv layout after ``-c``: mode host port user password payload.
SSH_CLIENT_SCRIPT = r"""
import hashlib, json, posixpath, sys

def emit(payload):
    print(json.dumps(payload))


def make_dirs(sftp, directory):
    # Recursive mkdir; an "already there" stat is success, a race on mkdir is
    # ignored (two operators may create the same parent concurrently).
    pending = []
    current = directory
    while current and current not in ("/", "."):
        pending.append(current)
        parent = posixpath.dirname(current)
        if parent == current:
            break
        current = parent
    for path in reversed(pending):
        try:
            sftp.stat(path)
        except IOError:
            try:
                sftp.mkdir(path)
            except IOError:
                pass

def main():
    mode, host, port, user, password, payload_raw = sys.argv[1:7]
    payload = json.loads(payload_raw)
    try:
        import paramiko
    except Exception as exc:
        emit({"ok": False, "error": "ssh_unavailable", "detail": str(exc)})
        return
    result = {"ok": False, "mode": mode, "host": host, "username": user}
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=int(port),
            username=user,
            password=password,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        result["connected"] = True
        if mode == "upload":
            local_path = payload["local_path"]
            remote_path = payload["remote_path"]
            sftp = client.open_sftp()
            try:
                if payload.get("make_dirs"):
                    make_dirs(sftp, posixpath.dirname(remote_path))
                sftp.put(local_path, remote_path)
                file_mode = payload.get("file_mode")
                if file_mode:
                    sftp.chmod(remote_path, int(str(file_mode), 8))
                stat = sftp.stat(remote_path)
                # Read the bytes back and hash them *on the target*: the sha256 in
                # the observation is the remote file's, never the local source's.
                digest = hashlib.sha256()
                remote_file = sftp.open(remote_path, "rb")
                try:
                    while True:
                        chunk = remote_file.read(65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                finally:
                    remote_file.close()
                result.update({
                    "ok": True,
                    "mode": "upload",
                    "remote_path": remote_path,
                    "uploaded_bytes": stat.st_size,
                    "remote_sha256": digest.hexdigest(),
                    "remote_mode": oct(stat.st_mode & 0o777),
                })
            finally:
                sftp.close()
        elif mode == "exec":
            command = payload.get("command", "")
            stdin_data = payload.get("stdin")
            # sudo reads the password from a tty; allocate a pty only when we
            # actually feed stdin, keeping normal commands pty-free.
            stdin, stdout, stderr = client.exec_command(
                command, timeout=payload.get("command_timeout", 60), get_pty=bool(stdin_data)
            )
            if stdin_data:
                stdin.write(stdin_data)
                stdin.flush()
                try:
                    stdin.channel.shutdown_write()
                except Exception:
                    pass
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
            result.update({"ok": True, "command": command, "stdout": out, "stderr": err, "exit_status": code})
        elif mode == "enum":
            commands = payload.get("commands", {})
            command_timeout = payload.get("command_timeout", 60)
            results = {}
            for key, command in commands.items():
                entry = {"command": command}
                try:
                    if key == "__SUDO__":
                        stdin, stdout, stderr = client.exec_command("sudo -n -l", timeout=command_timeout)
                        out = stdout.read().decode("utf-8", "replace")
                        err = stderr.read().decode("utf-8", "replace")
                        code = stdout.channel.recv_exit_status()
                        if code != 0:
                            # Non-interactive sudo failed: feed the password to -S
                            # over a pty (sudo reads the password from the tty).
                            stdin, stdout, stderr = client.exec_command(
                                "sudo -S -l", timeout=command_timeout, get_pty=True
                            )
                            stdin.write(password + "\n")
                            stdin.flush()
                            try:
                                stdin.channel.shutdown_write()
                            except Exception:
                                pass
                            out = stdout.read().decode("utf-8", "replace")
                            err = stderr.read().decode("utf-8", "replace")
                            code = stdout.channel.recv_exit_status()
                        entry.update({"stdout": out, "stderr": err, "exit_status": code})
                    else:
                        stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
                        entry["stdout"] = stdout.read().decode("utf-8", "replace")
                        entry["stderr"] = stderr.read().decode("utf-8", "replace")
                        entry["exit_status"] = stdout.channel.recv_exit_status()
                except Exception as exc:
                    entry["error"] = "%s: %s" % (type(exc).__name__, exc)
                results[key] = entry
            result.update({"ok": True, "results": results})
        else:
            result["error"] = "unsupported mode: %s" % mode
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    emit(result)

main()
"""


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _forbidden_command(command: str) -> str | None:
    lowered = command.lower()
    for token in SSH_FORBIDDEN_TOKENS:
        if token in lowered:
            return token
    return None


def parse_sudo_rules(text: str) -> list[dict[str, str]]:
    """Extract ``(who) command`` rules from ``sudo -l`` output."""
    rules: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        match = _SUDO_RULE_RE.match(line)
        if not match:
            continue
        rules.append({"who": match.group("who").strip(), "command": match.group("command").strip()})
    return rules


def ssh_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.ssh_exec``."""
    return ToolDefinition(
        tool_id="nexus.post.ssh_exec",
        effect="post_exploitation",
        name="SSH command execution",
        tenant_id=tenant_id,
        description=(
            "SSH: un comando con credential_ref (preferido) o password (manual). "
            "HIGH: requiere aprobación; rechaza comandos destructivos."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                **_credential_schema(),
                "command": {"type": "string", "minLength": 1, "maxLength": 4096},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600},
            },
            "required": ["target", "username", "command"],
            "anyOf": [{"required": ["password"]}, {"required": ["credential_ref"]}],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.post.ssh_exec"],
        timeout_seconds=600,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def enum_system_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.enum_system``."""
    return ToolDefinition(
        tool_id="nexus.post.enum_system",
        effect="post_exploitation",
        name="Linux post-exploitation enumeration",
        tenant_id=tenant_id,
        # V1-44 (rerun 12): the model saw `sudo -n -l` answer "a password is
        # required", read it as "sudo is unusable" and never called this tool,
        # which is the one that resolves exactly that. The first sentence is the
        # one that counts: ``render_tool_catalog`` shows the model only the first
        # ``CATALOG_DESCRIPTION_CHARS`` (64) characters of a description, so the
        # trigger and the resolution are stated up front and the rest is detail.
        description=(
            "Tras 'sudo: a password is required' resuelve sudo -l (vault). "
            "Inyecta la contraseña guardada con `sudo -S`; id, SUID, "
            "capabilities y cron en UNA llamada. No invoques sudo -l por "
            "nexus.post.ssh_exec: esta tool lo resuelve."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                **_credential_schema(),
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
            },
            "required": ["target", "username"],
            "anyOf": [{"required": ["password"]}, {"required": ["credential_ref"]}],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.post.enum_system"],
        timeout_seconds=900,
        max_output_bytes=4_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def ssh_upload_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.ssh_upload``."""
    return ToolDefinition(
        tool_id="nexus.post.ssh_upload",
        name="SSH file upload (SFTP)",
        tenant_id=tenant_id,
        description=(
            "Sube UN archivo del workspace al host por SFTP con credential_ref "
            "(preferido) o password (manual): p. ej. linPEAS cuando el objetivo "
            "no tiene salida a Internet. Verifica el sha256 remoto tras subirlo."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                **_credential_schema(),
                "local_path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1024,
                    "description": "Ruta del archivo dentro del workspace del engagement.",
                },
                "remote_path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": "Ruta destino en el objetivo (absoluta, p. ej. /tmp/pe.sh).",
                },
                "file_mode": {
                    "type": "string",
                    "pattern": "^[0-7]{3,4}$",
                    "description": "Modo octal opcional para el archivo remoto (p. ej. 755).",
                },
                "make_dirs": {
                    "type": "boolean",
                    "description": "Crea los directorios padre del destino si faltan.",
                },
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": SSH_MAX_TIMEOUT_SECONDS},
            },
            "required": ["target", "username", "local_path", "remote_path"],
            "anyOf": [{"required": ["password"]}, {"required": ["credential_ref"]}],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="exploit",
        required_permissions=["execute:tool:nexus.post.ssh_upload"],
        timeout_seconds=SSH_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _validate_remote_path(value: Any) -> str:
    """Return a target path free of control characters and traversal."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("remote_path is required")
    if len(text) > 4096:
        raise ValueError("remote_path is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("remote_path contains control characters")
    if any(part == ".." for part in text.split("/")):
        raise ValueError("remote_path must not contain traversal sequences")
    return text


def _validate_file_mode(value: Any) -> str:
    """Return an octal file mode (``"755"``) or ``""`` when unset."""
    text = str(value or "").strip()
    if not text:
        return ""
    if not SSH_FILE_MODE_RE.fullmatch(text):
        raise ValueError("file_mode must be an octal mode such as 755 or 0644")
    return text


async def _run_ssh_client(
    *, mode: str, host: str, port: int, username: str, password: str, payload: dict, timeout_seconds: int
) -> Any:
    argv = [
        "python3",
        "-c",
        SSH_CLIENT_SCRIPT,
        mode,
        host,
        str(port),
        username,
        password,
        json.dumps(payload),
    ]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=SSH_ALLOWED_PROGRAMS)
    return await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_SSH_IMAGE",
        default_image="python:3.12-alpine",
    )


#: Bound on the backend diagnostic echoed back to the model (V1-32). The client
#: reports ``"<ExceptionType>: <message>"``; it used to be dropped here, so a
#: failed SSH call answered ``exit_status: null`` with empty stdout/stderr and
#: neither the agent nor the operator could tell a wrong password from a dead
#: network. Measured in rerun 8, iterations 10/11/14.
SSH_ERROR_DETAIL_MAX = 300

#: Accepted credential arguments. ``credential_ref`` is the handle the agent
#: carries (resolved by the gateway, V1-29); ``password`` stays for manual use.
SSH_CREDENTIAL_REF = {
    "type": "string",
    "pattern": "^vault:[a-f0-9]{32}$",
    "description": (
        "Handle of a stored credential (secret vault). Preferido sobre "
        "`password`; el plaintext se resuelve dentro del proceso de la tool."
    ),
}


def _credential_schema(*, include_password: bool = True) -> dict[str, Any]:
    """Properties plus the ``password``-or-``credential_ref`` constraint."""
    properties: dict[str, Any] = {"credential_ref": dict(SSH_CREDENTIAL_REF)}
    if include_password:
        properties["password"] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "description": "Contraseña en claro (uso manual).",
        }
    return properties


def _credential_detail(payload: dict[str, Any]) -> str:
    """Bounded backend diagnostic of an SSH client payload (V1-32)."""
    detail = str(payload.get("error") or "").strip()
    if not detail:
        return ""
    return detail[:SSH_ERROR_DETAIL_MAX]


def _parse_client_json(stdout: str) -> dict[str, Any]:
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("ssh client did not return a JSON result")


async def ssh_exec_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run one command over SSH through the sandbox."""
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    command = str(arguments.get("command") or "").strip()
    if not command:
        raise ValueError("command is required")
    forbidden = _forbidden_command(command)
    if forbidden is not None:
        raise ValueError(f"command contains a forbidden token: {forbidden!r}")
    # ``sudo`` needs a password on a non-interactive channel. Reuse the login
    # credential (the common case) via ``sudo -S`` and feed it on stdin, so the
    # secret never appears in the remote argv.
    stdin_data: str | None = None
    remote_command = command
    if command.startswith("sudo ") and " -S" not in command[:16]:
        remote_command = "sudo -S " + command[len("sudo ") :]
        stdin_data = password + "\n"
    port = int(arguments.get("port") or SSH_DEFAULT_PORT)
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SSH_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else SSH_DEFAULT_TIMEOUT_SECONDS),
    )

    result = await _run_ssh_client(
        mode="exec",
        host=target,
        port=port,
        username=username,
        password=password,
        payload={
            "command": remote_command,
            "command_timeout": min(60, timeout_seconds),
            "stdin": stdin_data,
        },
        timeout_seconds=timeout_seconds,
    )
    evidence = {
        "mode": "exec",
        "command": command,
        "sudo_stdin": stdin_data is not None,
        "port": port,
        "username": username,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "ssh command timed out", "target": target},
            verified=False,
            verification_method="ssh_exec_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )
    try:
        payload = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="ssh_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if payload.get("error") == "ssh_unavailable":
        return ToolResult(
            output={"error": "paramiko is not available in the ssh sandbox"},
            verified=False,
            verification_method="ssh_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
        )
    ok = bool(payload.get("ok")) and bool(payload.get("connected"))
    evidence["exit_status"] = payload.get("exit_status")
    detail = "" if ok else _credential_detail(payload)
    if detail:
        # V1-32: the reason the channel failed belongs in the observation.
        evidence["error_detail"] = detail
    output: dict[str, Any] = {
        "target": target,
        "command": command,
        "stdout": payload.get("stdout", ""),
        "stderr": payload.get("stderr", ""),
        "exit_status": payload.get("exit_status"),
    }
    if detail:
        output["error"] = detail
    return ToolResult(
        output=output,
        verified=ok,
        verification_method="ssh_exec_completed" if ok else "ssh_exec_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


async def enum_system_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Collect the Linux privilege-escalation surface over SSH."""
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    port = int(arguments.get("port") or SSH_DEFAULT_PORT)
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SSH_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else ENUM_DEFAULT_TIMEOUT_SECONDS),
    )

    result = await _run_ssh_client(
        mode="enum",
        host=target,
        port=port,
        username=username,
        password=password,
        payload={"commands": ENUM_COMMANDS, "command_timeout": min(90, timeout_seconds)},
        timeout_seconds=timeout_seconds,
    )
    evidence: dict[str, Any] = {
        "mode": "enum",
        "port": port,
        "username": username,
        "commands": sorted(ENUM_COMMANDS),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "enumeration timed out", "target": target},
            verified=False,
            verification_method="enum_system_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )
    try:
        payload = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="enum_system_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if payload.get("error") == "ssh_unavailable":
        return ToolResult(
            output={"error": "paramiko is not available in the ssh sandbox"},
            verified=False,
            verification_method="ssh_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
        )
    results = payload.get("results") or {}
    sudo_output = (results.get(SSH_ENUM_MARKER) or {}).get("stdout", "")
    sudo_rules = parse_sudo_rules(sudo_output)
    evidence.update(
        {
            "commands_run": len(results),
            "sudo_rules": [rule["command"] for rule in sudo_rules],
        }
    )
    ok = bool(payload.get("ok")) and bool(payload.get("connected"))
    detail = "" if ok else _credential_detail(payload)
    if detail:
        # V1-32: without this the failure was unreadable (empty results, no
        # stdout): the agent could not tell a bad password from a dead link.
        evidence["error_detail"] = detail
    output: dict[str, Any] = {
        "target": target,
        "username": username,
        "results": results,
        "sudo_rules": sudo_rules,
    }
    if detail:
        output["error"] = detail
    return ToolResult(
        output=output,
        verified=ok,
        verification_method="enum_system_completed" if ok else "enum_system_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


async def ssh_upload_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Upload one workspace file to a host over SFTP and verify its sha256.

    The post-condition is the point of this handler: a tool that drops a payload
    on a target is only useful if the operator can trust that the bytes that
    landed are the bytes that were sent. The local sha256 is computed here and
    the remote one is computed by the client *on the target*, so a partial
    transfer, a full disk or an ``scp``-style redirect surfaces as a declared
    negative instead of a green check.
    """
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    remote_path = _validate_remote_path(arguments.get("remote_path"))
    file_mode = _validate_file_mode(arguments.get("file_mode"))
    make_dirs = bool(arguments.get("make_dirs", False))
    # The source is confined to the engagement workspace, exactly like the
    # multipart upload of ``nexus.web.request``: a missing path or a ``..``
    # escape is refused before anything touches the network.
    source = resolve_workspace_path(
        str(arguments.get("local_path") or ""),
        root=os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd()),
    )
    port = int(arguments.get("port") or SSH_DEFAULT_PORT)
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SSH_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else UPLOAD_DEFAULT_TIMEOUT_SECONDS),
    )
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    local_sha256 = digest.hexdigest()
    local_bytes = source.stat().st_size

    result = await _run_ssh_client(
        mode="upload",
        host=target,
        port=port,
        username=username,
        password=password,
        payload={
            "local_path": str(source),
            "remote_path": remote_path,
            "file_mode": file_mode or None,
            "make_dirs": make_dirs,
        },
        timeout_seconds=timeout_seconds,
    )
    evidence: dict[str, Any] = {
        "mode": "upload",
        "port": port,
        "username": username,
        "local_path": str(source),
        "remote_path": remote_path,
        "local_bytes": local_bytes,
        "local_sha256": local_sha256,
        "file_mode": file_mode or None,
        "make_dirs": make_dirs,
        "timeout_seconds": timeout_seconds,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "ssh upload timed out", "target": target},
            verified=False,
            verification_method="ssh_upload_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )
    try:
        payload = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="ssh_upload_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if payload.get("error") == "ssh_unavailable":
        return ToolResult(
            output={"error": "paramiko is not available in the ssh sandbox"},
            verified=False,
            verification_method="ssh_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
        )
    uploaded = bool(payload.get("ok")) and bool(payload.get("connected"))
    remote_sha256 = str(payload.get("remote_sha256") or "")
    evidence.update(
        {
            "uploaded_bytes": payload.get("uploaded_bytes"),
            "remote_sha256": remote_sha256 or None,
            "remote_mode": payload.get("remote_mode"),
            "error": payload.get("error"),
        }
    )
    if not uploaded:
        return ToolResult(
            output={
                "target": target,
                "remote_path": remote_path,
                "local_path": str(source),
                "uploaded_bytes": payload.get("uploaded_bytes"),
                "remote_sha256": remote_sha256 or None,
                "error": payload.get("error") or "ssh upload failed",
            },
            verified=False,
            verification_method="ssh_upload_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if remote_sha256 != local_sha256:
        return ToolResult(
            output={
                "target": target,
                "remote_path": remote_path,
                "local_path": str(source),
                "local_sha256": local_sha256,
                "remote_sha256": remote_sha256 or None,
                "uploaded_bytes": payload.get("uploaded_bytes"),
                "error": "remote sha256 does not match the local source",
            },
            verified=False,
            verification_method="ssh_upload_hash_mismatch",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    return ToolResult(
        output={
            "target": target,
            "username": username,
            "local_path": str(source),
            "remote_path": remote_path,
            "uploaded_bytes": payload.get("uploaded_bytes"),
            "sha256": remote_sha256,
            "remote_mode": payload.get("remote_mode"),
        },
        verified=True,
        verification_method="ssh_upload_verified_sha256",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "ENUM_COMMANDS",
    "SSH_CLIENT_SCRIPT",
    "enum_system_definition",
    "enum_system_handler",
    "parse_sudo_rules",
    "ssh_exec_definition",
    "ssh_exec_handler",
    "ssh_upload_definition",
    "ssh_upload_handler",
]
