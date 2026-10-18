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
  persisted by these handlers. The client closes the transport in a ``finally``
  and :func:`_run_ssh_client` serializes sessions to the same target with a
  quiet period between them: Simple CTF answered ``Authentication failed`` to
  the second and third connection opened seconds apart, and the agent read that
  as a bad password. Serializing plus pacing is what keeps ``sshd``/fail2ban
  from treating our own recon as a brute-force attempt.
* Plan B (Simple CTF runs 1 and 2): when the login is refused for a credential
  the blackboard already proved valid, ``ssh_exec`` replays the command through
  ``nexus.shell.exec`` with the native ``ssh`` client driven by ``sshpass``
  (:func:`_run_sshpass_fallback`). No second paramiko session is opened, and
  the password travels on stdin (``sshpass -d 0``), never in an argv.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import shutil
import threading
import time
from dataclasses import dataclass, field, replace
from functools import wraps
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.redaction import redact_secret_values
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

#: Quiet period between the end of one SSH session and the next connection to
#: the same target. The previous one-second window still produced
#: ``Authentication failed`` on the second connection in Simple CTF, so the gate
#: now waits three full seconds -long enough to clear one ``sshd``/fail2ban
#: observation interval, still far below a brute-force sweep. Overridable in
#: tests.
SSH_CONNECT_COOLDOWN_SECONDS = 3.0

#: Plan B of the SSH handlers: when the target refuses a credential that the
#: blackboard already proved valid, the command is replayed with the native
#: ``ssh`` client driven by ``sshpass``. This bypasses paramiko entirely, which
#: is what the target's rate limiter was answering as a burst of logins.
SSHPASS_BINARY = "sshpass"

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

#: ``sudo`` options that mean "never ask for a password".
SUDO_NON_INTERACTIVE_FLAGS: tuple[str, ...] = ("-n", "--non-interactive")

#: Where the first shell command of a line ends (``;``, ``&&``, ``||``, ``|``).
_SHELL_SEPARATOR_RE = re.compile(r"[;&|\n]")

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
    # ``connected`` separates the two failures this client can produce: the login
    # itself (bad or refused credential) and anything that breaks *after* the
    # login (the command, the channel). Only the first one is authentication.
    connected = False
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
        connected = True
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
            # Never allocate a pty when a secret travels on stdin: a pty echoes
            # what is written to it, and ``sudo -S`` reads the password from the
            # pipe perfectly well. V1-46 (rerun 13): the pty echoed the vault
            # password of a ``sudo -n`` command straight into the observation.
            stdin, stdout, stderr = client.exec_command(
                command, timeout=payload.get("command_timeout", 60), get_pty=False
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
            if code != 0:
                # The login worked; the command is what failed. Saying so here is
                # what stops the caller from blaming the credential.
                result.update({"ok": False, "outcome": "command_failed"})
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
                            # Non-interactive sudo failed: feed the password to -S.
                            # No pty here either (V1-46): sudo reads the password
                            # from the pipe, and a pty would echo it if sudo never
                            # got to consume it. Same invariant everywhere -no pty
                            # on a channel that carries the secret- at the cost of
                            # hosts with ``Defaults requiretty``, where the
                            # escalation fails closed instead of leaking.
                            stdin, stdout, stderr = client.exec_command(
                                "sudo -S -l", timeout=command_timeout, get_pty=False
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
        if connected:
            # A successful login is proof the credential is right: never report
            # this as an authentication failure (Simple CTF: ``sudo -l`` failed
            # after an established session, the client said
            # "AuthenticationException", and the agent went on to assume the SSH
            # password was wrong and looped until the timeout).
            result.update({
                "ok": False,
                "connected": True,
                "outcome": "command_failed",
                # The class name is deliberately left out: rewriting
                # ``AuthenticationException`` as text is exactly what made the
                # measured agent hunt a credential that was already valid.
                "error": (
                    "CommandFailed: the SSH session was established and the "
                    "command failed (%s)" % (str(exc) or type(exc).__name__)
                ),
                "exit_status": int(result.get("exit_status") or 1),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
            })
        else:
            result.update({
                "ok": False,
                "connected": False,
                "error": "%s: %s" % (type(exc).__name__, exc),
                "error_kind": "connect_failed",
            })
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    emit(result)

main()
"""


@dataclass
class _SSHGate:
    """One target's connection slot: at most one session, then a cooldown.

    The gate is bound to the event loop that created it. Handlers run on the
    app's loop; tests that use one ``asyncio.run`` per call get a fresh gate
    instead of a lock attached to a closed loop.
    """

    loop: asyncio.AbstractEventLoop
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    #: Monotonic time before which the next connection must not open.
    ready_at: float = 0.0


#: Gates keyed by ``(host, port)``. Guarded by a plain lock because the dict is
#: also read from a different loop when the process runs several of them.
_SSH_GATES: dict[tuple[str, int], _SSHGate] = {}
_SSH_GATES_LOCK = threading.Lock()


def _ssh_gate(host: str, port: int) -> _SSHGate:
    """The gate of ``(host, port)`` for the running loop, pruned when stale."""
    loop = asyncio.get_running_loop()
    key = (host, port)
    with _SSH_GATES_LOCK:
        gate = _SSH_GATES.get(key)
        if gate is None or gate.loop is not loop:
            gate = _SSHGate(loop=loop)
            _SSH_GATES[key] = gate
        if len(_SSH_GATES) > 64:
            stale = [
                other_key
                for other_key, other in _SSH_GATES.items()
                if other is not gate
                and (other.loop.is_closed() or other.ready_at < _now() - 60)
            ]
            for other_key in stale:
                _SSH_GATES.pop(other_key, None)
        return gate


def _now() -> float:
    """Monotonic clock of the gate (patchable in tests)."""
    return time.monotonic()


async def _wait_for_ssh_slot(gate: _SSHGate) -> None:
    """Sleep until the target's cooldown expires (no-op on a cold target)."""
    delay = gate.ready_at - _now()
    if delay > 0:
        await asyncio.sleep(delay)


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


def sudo_needs_no_password(command: str) -> bool:
    """Whether the command tells ``sudo`` not to ask for a password (V1-46).

    Deliberately conservative: a ``-n``/``--non-interactive`` token anywhere in
    the first shell segment of a command that starts with ``sudo`` disables the
    stdin injection, even when the flag belongs to the wrapped program
    (``sudo tar cf x -n``). The two mistakes are not symmetric: a false positive
    costs one call that answers ``sudo: a password is required`` and fails closed
    (no pty, empty stdin), while a false negative hands the vault password to a
    ``sudo`` that will not read it -and the pty's echo then prints it into the
    observation, which is what the rerun 13 measured.
    """
    rest = command.removeprefix("sudo")
    segment = _SHELL_SEPARATOR_RE.split(rest, maxsplit=1)[0]
    for token in segment.split():
        if token in SUDO_NON_INTERACTIVE_FLAGS:
            return True
        # A clustered short flag carries it too (``sudo -nl``). Long options are
        # skipped: the flags of the wrapped command are irrelevant here and a
        # ``--flag`` can never be a sudo short option.
        if token.startswith("-") and not token.startswith("--") and "n" in token[1:]:
            return True
    return False


def _secret_values(password: Any) -> tuple[str, ...]:
    """The literals of this invocation that must never reach an observation.

    ``password`` is the argument the *gateway* fills in when it resolves a
    ``credential_ref`` (V1-29), so this covers both entry points: the model's
    manual plaintext and the vault secret it never sees.
    """
    return tuple(value for value in {str(password or "")} if value)


def _redact_output(payload: Any, secrets: tuple[str, ...]) -> Any:
    """Apply the value-based redaction to every string of a handler result."""
    if isinstance(payload, dict):
        return {key: _redact_output(value, secrets) for key, value in payload.items()}
    if isinstance(payload, (list, tuple)):
        return [_redact_output(item, secrets) for item in payload]
    if isinstance(payload, str):
        return redact_secret_values(payload, secrets)
    return payload


def _redact_credential_from_result(handler: Any) -> Any:
    """Never let the resolved credential reach the model or the ledger (V1-46).

    Applied once, at the boundary of the three SSH handlers, so no return branch
    can forget it: the observation (``output``), the evidence, and the raw client
    capture (``stdout``/``stderr``) all pass through the same redactor. The
    upstream defences stay: the secret is not in the remote argv and the gateway
    keeps it out of the audit trail -this closes the *target's* echo.

    It is also where the arguments are completed from the engagement board
    (:func:`_resolve_transport`): the port and the credential the engagement
    already proved are filled *before* the handler runs, so the redactor covers
    the secret it just resolved as well.
    """

    @wraps(handler)
    async def invoke(arguments: dict, context: RunContext) -> ToolResult:
        arguments, resolved = _resolve_transport(arguments or {}, context)
        result = await handler(arguments, context)
        if resolved:
            evidence = dict(result.evidence) if isinstance(result.evidence, dict) else {}
            evidence["resolved_from_board"] = resolved
            result = replace(result, evidence=evidence)
        secrets = _secret_values(arguments.get("password"))
        if not secrets:
            return result
        return replace(
            result,
            output=_redact_output(result.output, secrets),
            evidence=_redact_output(result.evidence, secrets),
            stdout=redact_secret_values(result.stdout, secrets),
            stderr=redact_secret_values(result.stderr, secrets),
        )

    return invoke


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
    # One session at a time per target, and never sooner than the cooldown after
    # the previous one ended. ``sshd`` (and any ban daemon in front of it) sees a
    # single, paced client instead of three parallel ones from the same IP.
    gate = _ssh_gate(host, port)
    async with gate.lock:
        await _wait_for_ssh_slot(gate)
        try:
            return await run_in_sandbox(
                sandbox,
                argv,
                timeout_seconds=timeout_seconds,
                image_env="NEXUS_SSH_IMAGE",
                default_image="python:3.12-alpine",
            )
        finally:
            # The cooldown starts when the client process is gone, which is when
            # the remote side has seen the disconnect.
            gate.ready_at = _now() + SSH_CONNECT_COOLDOWN_SECONDS


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
        "`password`; el plaintext se resuelve dentro del proceso de la tool. "
        "Puedes omitirlo: si el engagement ya probó una credencial SSH para "
        "ese usuario y host, el motor la usa."
    ),
}


def _credential_schema(*, include_password: bool = True) -> dict[str, Any]:
    """Credential properties; omitting both means "use the proved one".

    The schema deliberately does **not** require ``password``/``credential_ref``
    (the old ``anyOf`` rejected the call before the handler could look the
    credential up on the board, and a rejected call still counted as a
    consecutive failure -measured in the Simple CTF run of 2026-10-17, 23:16
    UTC: iteration 27 was rejected for that reason and the run died five turns
    later).
    """
    properties: dict[str, Any] = {"credential_ref": dict(SSH_CREDENTIAL_REF)}
    if include_password:
        properties["password"] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "description": (
                "Contraseña en claro (uso manual). Omítela junto a "
                "`credential_ref` y la tool usa la credencial que el "
                "engagement ya validó para ese usuario/host."
            ),
        }
    return properties


def _credential_detail(payload: dict[str, Any]) -> str:
    """Bounded backend diagnostic of an SSH client payload (V1-32)."""
    detail = str(payload.get("error") or "").strip()
    if not detail:
        return ""
    return detail[:SSH_ERROR_DETAIL_MAX]


#: Fragments that mean the *login* was refused (wrong credential or a server
#: that does not accept password authentication). Only consulted when the client
#: never reached an authenticated session: after a successful login the same
#: exception text describes the command, not the credential.
_AUTH_FAILURE_MARKERS = (
    "authenticationexception",
    "authentication failed",
    "permission denied (publickey",
)


def _is_authentication_failure(detail: str) -> bool:
    """Whether a pre-login diagnostic reports a refused credential."""
    lowered = (detail or "").lower()
    return any(marker in lowered for marker in _AUTH_FAILURE_MARKERS)


def _verified_ssh_access(context: RunContext, target: str, username: str) -> bool:
    """Whether the blackboard already proved this SSH credential works.

    Plan B only makes sense for a credential the engine *already* validated: a
    genuinely bad password must stay ``denied`` and must never be replayed
    against a rate limiter. The proof is the verified ``access`` fact a
    successful ``ssh_exec`` derives (``value = {"transport": "ssh",
    "username": …}``) or the ``cred:ssh:<user>@<target>`` vault handle.
    """
    store = getattr(context, "store", None)
    engagement_id = str(getattr(context, "engagement_id", "") or "")
    if store is None or not engagement_id:
        return False
    from nexus_core.kernel.blackboard import Blackboard, is_verified_fact

    try:
        facts = Blackboard(store).list_facts(context.tenant_id, engagement_id)
    except Exception:  # noqa: BLE001 - a failed lookup must not break the tool
        return False
    for fact in facts:
        if not is_verified_fact(fact):
            continue
        value = fact.get("value") or {}
        if (
            fact.get("fact_type") == "access"
            and str(fact.get("key") or "") == target
            and str(value.get("transport") or "") == "ssh"
            and str(value.get("username") or "") == username
        ):
            return True
        if (
            fact.get("fact_type") == "credential"
            and str(fact.get("key") or "") == f"cred:ssh:{username}@{target}"
        ):
            return True
    return False


def _board_facts(context: RunContext, fact_type: str) -> list[dict[str, Any]]:
    """Facts of ``fact_type`` on the engagement board (never raises)."""
    store = getattr(context, "store", None)
    engagement_id = str(getattr(context, "engagement_id", "") or "")
    if store is None or not engagement_id:
        return []
    from nexus_core.kernel.blackboard import Blackboard

    try:
        facts = Blackboard(store).list_facts(
            getattr(context, "tenant_id", "system"), engagement_id, fact_type=fact_type
        )
    except Exception:  # noqa: BLE001 - an unreadable board never breaks a tool
        return []
    return [fact for fact in facts if isinstance(fact, dict)]


def _board_port(value: Any) -> int | None:
    """One port out of a fact value, or ``None`` when it is not a port."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _known_ssh_port(context: RunContext, target: str, username: str = "") -> int | None:
    """SSH port the engagement already proved, or ``None`` (never a guess).

    Two verified sources, strongest first: the ``access`` fact of the session
    that really authenticated (it carries the port it used) and a ``service``
    fact whose description names SSH on this host. Measured in Simple CTF
    (2026-10-17): the target runs sshd on 2222, the model omitted ``port`` in
    its last three turns, ``ssh_exec`` fell back to 22, spent 20 s timing out and
    the run closed with three consecutive failures -the credential it needed was
    already on the board.
    """
    for fact in _board_facts(context, "access"):
        value = fact.get("value") or {}
        if str(fact.get("key") or "") != target:
            continue
        if str(value.get("transport") or "") != "ssh":
            continue
        if username and str(value.get("username") or "") != username:
            continue
        port = _board_port(value.get("port"))
        if port:
            return port
    for fact in _board_facts(context, "service"):
        key = str(fact.get("key") or "")
        if key and not key.startswith(f"{target}:"):
            continue
        value = fact.get("value") or {}
        described = " ".join(
            str(value.get(field) or "") for field in ("service", "product", "extra_info")
        ).lower()
        if "ssh" not in described:
            continue
        port = _board_port(value.get("port"))
        if port:
            return port
    return None


def _board_ssh_credential(context: RunContext, target: str, username: str) -> str:
    """Plaintext of the SSH credential the board already proved, else ``""``.

    Only a *verified* credential fact is reused (V1-29): ``cred:ssh:<user>@<host>``
    carries the ``secret_ref`` handle and the plaintext stays in the vault, so a
    guessed password is never replayed as if an authenticated session had proved
    it. Without this, the password the model discovered in one turn had to be
    retyped on every later turn -and the measured run retyped a *wrong* one.
    """
    from nexus_core.kernel.blackboard import is_verified_fact
    from nexus_core.kernel.secret_store import default_secret_store, is_secret_ref

    wanted = f"cred:ssh:{username}@{target}"
    for fact in _board_facts(context, "credential"):
        if not is_verified_fact(fact) or str(fact.get("key") or "") != wanted:
            continue
        ref = str((fact.get("value") or {}).get("secret_ref") or "")
        if not is_secret_ref(ref):
            continue
        try:
            return default_secret_store().get(
                ref, tenant_id=getattr(context, "tenant_id", "system")
            ).decode("utf-8")
        except Exception:  # noqa: BLE001 - an unreadable handle is not a credential
            return ""
    return ""


def _resolve_transport(arguments: dict, context: RunContext) -> tuple[dict, dict[str, Any]]:
    """Complete ``arguments`` from the engagement board: port and credential.

    Returns the completed copy plus what was resolved (for the evidence, so the
    operator and the model can see that the engine -not the model- supplied it).
    Both facts are *verified* board evidence: the SSH port of the target and the
    credential an authenticated session already proved. The model still owns the
    manual path: an explicit ``password``/``credential_ref``/``port`` is never
    overridden.
    """
    resolved: dict[str, Any] = {}
    target = str(arguments.get("target") or "")
    username = str(arguments.get("username") or "")
    filled = dict(arguments)
    if target and not filled.get("port"):
        port = _known_ssh_port(context, target, username)
        if port:
            filled["port"] = port
            resolved["port"] = port
    if target and username and not filled.get("password") and not filled.get("credential_ref"):
        password = _board_ssh_credential(context, target, username)
        if password:
            filled["password"] = password
            resolved["credential"] = f"vault:cred:ssh:{username}@{target}"
    return filled, resolved


def _sshpass_argv(*, host: str, port: int, username: str, command: str) -> list[str]:
    """Native ``ssh`` invocation driven by ``sshpass`` (Plan B).

    ``-d 0`` takes the password from stdin instead of ``-p`` / ``-e``: the secret
    never reaches the command line, so it cannot land in the shell audit, the
    artifact or the model's observation. ``sshpass`` reads exactly one line and
    the rest of stdin reaches the remote command (that is what ``sudo -S``
    consumes when the original call injected a password there).
    """
    return [
        SSHPASS_BINARY,
        "-d",
        "0",
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=20",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-p", str(port),
        f"{username}@{host}",
        command,
    ]


async def _run_sshpass_fallback(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
    stdin_data: str | None,
    timeout_seconds: int,
    context: RunContext,
) -> ToolResult | None:
    """Replay ``command`` through ``nexus.shell.exec`` + native ``ssh``.

    Returns ``None`` when ``sshpass`` is not installed, so the caller keeps the
    original determinate ``denied`` result and says why Plan B was not tried.
    The replay never touches paramiko: a fresh native client after the auth
    refusal is exactly the escape hatch the measured Simple CTF runs needed,
    where the credential was right and the server refused the *next* session.
    """
    if shutil.which(SSHPASS_BINARY) is None:
        return None
    # Imported lazily: ``shell_exec_local`` imports the sandbox/workspace layer
    # and this module is also imported at registry build time.
    from .shell_exec_local import shell_exec_handler

    # ``sshpass -d 0`` consumes the first line; when the original call injected
    # the password into ``sudo -S`` on stdin, the second line reaches the remote
    # command exactly as it did over paramiko.
    remote_stdin = password + "\n"
    if stdin_data:
        remote_stdin += stdin_data
    invocation = shlex.join(
        _sshpass_argv(host=host, port=port, username=username, command=command)
    )
    result = await shell_exec_handler(
        {
            "command": invocation,
            "stdin": remote_stdin,
            "timeout_seconds": max(5, min(300, timeout_seconds)),
        },
        context,
    )
    summary = str(result.output.get("summary") or "")
    exit_status = result.exit_code
    evidence: dict[str, Any] = {
        "fallback_transport": "sshpass",
        "fallback_command": command,
        "exit_status": exit_status,
        "artifact_ref": result.output.get("artifact_ref"),
    }
    if "sshpass" in summary.lower() and exit_status in (None, 127):
        return ToolResult(
            output={
                "target": host,
                "command": command,
                "stdout": summary,
                "stderr": "",
                "exit_status": exit_status,
                "error": "sshpass fallback is not available in the local sandbox",
            },
            verified=False,
            outcome="unavailable",
            verification_method="ssh_exec_sshpass_unavailable",
            evidence=evidence,
            exit_code=exit_status,
        )
    if result.verified:
        return ToolResult(
            output={
                "target": host,
                "command": command,
                "stdout": summary,
                "stderr": "",
                "exit_status": exit_status,
                "fallback": "sshpass",
            },
            verified=True,
            verification_method="ssh_exec_sshpass_completed",
            evidence=evidence,
            exit_code=exit_status,
            accepted_exit_codes=(0,),
            stdout=summary,
        )
    return ToolResult(
        output={
            "target": host,
            "command": command,
            "stdout": summary,
            "stderr": "",
            "exit_status": exit_status,
            "error": "sshpass fallback failed after a refused paramiko login",
        },
        verified=False,
        outcome="command_failed",
        verification_method="ssh_exec_sshpass_failed",
        evidence=evidence,
        exit_code=exit_status,
    )


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
        # Fail closed, but say the whole way out: the engine already looks the
        # credential up on the board (V1-29 continuity), so this only fires when
        # the engagement has no proved SSH credential for that user and host.
        raise ValueError(
            "no SSH credential for "
            f"{username}@{target}: pass `password`, use the `credential_ref` "
            "handle, or authenticate once so the engine records the credential "
            "and can reuse it (enumerate with nexus.cred.bruteforce or a manual "
            "`ssh_exec` with the password)."
        )
    command = str(arguments.get("command") or "").strip()
    if not command:
        raise ValueError("command is required")
    forbidden = _forbidden_command(command)
    if forbidden is not None:
        raise ValueError(f"command contains a forbidden token: {forbidden!r}")
    # ``sudo`` needs a password on a non-interactive channel. Reuse the login
    # credential (the common case) via ``sudo -S`` and feed it on stdin, so the
    # secret never appears in the remote argv ... but only when sudo is allowed to
    # read it: with ``-n``/``--non-interactive`` the password is not consumed, and
    # the target's echo then prints it into the observation (V1-46, rerun 13).
    stdin_data: str | None = None
    remote_command = command
    sudo_stdin_skipped = ""
    if command.startswith("sudo ") and " -S" not in command[:16]:
        if sudo_needs_no_password(command):
            sudo_stdin_skipped = "non_interactive_flag"
        else:
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
    if sudo_stdin_skipped:
        # Audited rather than silent: the operator can see that this call did not
        # get the credential, and why.
        evidence["sudo_stdin_skipped"] = sudo_stdin_skipped
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
    # ``connected`` is the fact that decides *what* failed. A non-zero remote
    # exit status used to be a verified success (the client process exited 0),
    # and any failure was a bare ``RuntimeError`` that read as a bad credential;
    # the Simple CTF run spent its last iterations re-authenticating because of
    # it.
    connected = bool(payload.get("connected"))
    detail = _credential_detail(payload)
    raw_exit_status = payload.get("exit_status")
    try:
        exit_status = int(raw_exit_status) if raw_exit_status is not None else None
    except (TypeError, ValueError):
        exit_status = None
    evidence["exit_status"] = exit_status
    evidence["connected"] = connected
    output: dict[str, Any] = {
        "target": target,
        "command": command,
        "stdout": payload.get("stdout", ""),
        "stderr": payload.get("stderr", ""),
        "exit_status": exit_status,
    }
    if not connected:
        # The login itself failed: the credential (or the link) was refused, and
        # the invocation still decided something, so it is a determinate result
        # instead of an invariant the gateway turns into ``RuntimeError``.
        if detail:
            evidence["error_detail"] = detail
        output["error"] = detail or "ssh connection failed"
        denied = _is_authentication_failure(detail)
        if denied and password:
            # Plan B: a credential the board already proved valid is not retried
            # against paramiko -the target just refused *that* session. Replay
            # the command with the native client through ``sshpass``.
            if _verified_ssh_access(context, target, username):
                replacement = await _run_sshpass_fallback(
                    host=target,
                    port=port,
                    username=username,
                    password=password,
                    command=remote_command,
                    stdin_data=stdin_data,
                    timeout_seconds=timeout_seconds,
                    context=context,
                )
                if replacement is not None:
                    return replacement
                evidence["fallback"] = {
                    "attempted": False,
                    "reason": "sshpass_not_installed",
                }
                output["guidance"] = (
                    "La credencial ya está validada en el tablero, pero `sshpass` "
                    "no está instalado en el Kali del operador: instálalo para "
                    "usar el plan B (ssh nativo) o espacia las conexiones."
                )
            else:
                evidence["fallback"] = {
                    "attempted": False,
                    "reason": "no_verified_credential",
                }
        return ToolResult(
            output=output,
            verified=False,
            outcome="denied" if denied else "unavailable",
            verification_method=(
                "ssh_exec_authentication_failed" if denied else "ssh_exec_unreachable"
            ),
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    failed = bool(detail) or exit_status != 0
    if not failed:
        return ToolResult(
            output=output,
            verified=True,
            verification_method="ssh_exec_completed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if "authenticationexception" in detail.lower():
        # The client already translates this; the guarantee is kept here too so
        # no payload shape can report an established session as a login failure.
        detail = re.sub(
            r"^AuthenticationException:\s*", "CommandFailed: ", detail, flags=re.IGNORECASE
        )
    exit_status = exit_status if exit_status not in (None, 0) else 1
    output["exit_status"] = exit_status
    if detail:
        # V1-32: the reason the command failed belongs in the observation.
        output["error"] = detail
        evidence["error_detail"] = detail
    evidence["exit_status"] = exit_status
    # The *real* streams of the remote command, not the JSON envelope of the
    # client: the model has to read `sudo: a password is required` to pivot.
    evidence["stdout"] = output["stdout"]
    evidence["stderr"] = output["stderr"]
    return ToolResult(
        output=output,
        verified=False,
        outcome="command_failed",
        verification_method="ssh_exec_command_failed",
        evidence=evidence,
        exit_code=exit_status,
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
        # Fail closed, but say the whole way out: the engine already looks the
        # credential up on the board (V1-29 continuity), so this only fires when
        # the engagement has no proved SSH credential for that user and host.
        raise ValueError(
            "no SSH credential for "
            f"{username}@{target}: pass `password`, use the `credential_ref` "
            "handle, or authenticate once so the engine records the credential "
            "and can reuse it (enumerate with nexus.cred.bruteforce or a manual "
            "`ssh_exec` with the password)."
        )
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
        # Fail closed, but say the whole way out: the engine already looks the
        # credential up on the board (V1-29 continuity), so this only fires when
        # the engagement has no proved SSH credential for that user and host.
        raise ValueError(
            "no SSH credential for "
            f"{username}@{target}: pass `password`, use the `credential_ref` "
            "handle, or authenticate once so the engine records the credential "
            "and can reuse it (enumerate with nexus.cred.bruteforce or a manual "
            "`ssh_exec` with the password)."
        )
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


# V1-46: the three handlers that receive a credential run behind the same
# redaction boundary, so every return branch (success, timeout, parse failure,
# backend error) is covered by construction.
ssh_exec_handler = _redact_credential_from_result(ssh_exec_handler)
enum_system_handler = _redact_credential_from_result(enum_system_handler)
ssh_upload_handler = _redact_credential_from_result(ssh_upload_handler)

__all__ = [
    "ENUM_COMMANDS",
    "SSH_CLIENT_SCRIPT",
    "SUDO_NON_INTERACTIVE_FLAGS",
    "enum_system_definition",
    "enum_system_handler",
    "parse_sudo_rules",
    "ssh_exec_definition",
    "ssh_exec_handler",
    "ssh_upload_definition",
    "ssh_upload_handler",
    "sudo_needs_no_password",
]
