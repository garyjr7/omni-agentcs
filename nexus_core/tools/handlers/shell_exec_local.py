"""Universal local shell (WP1): ``nexus.shell.exec``.

The measured problem
--------------------
OMNI had 68 rigid tools and no way to run ``jadx``, ``john``, ``git-dumper``,
a Python script or ``tmux``: the kill chain stopped exactly where FreeBuff
keeps going. This handler is the execution substrate that closes that gap.

What it guarantees (and what it does not)
-----------------------------------------
* **Every process goes through :func:`sandbox_for_environment`** - never
  ``shell=True`` and never a raw ``create_subprocess_exec``. The child is
  ``bash -lc <command>`` *inside* the governed sandbox, so workspace
  confinement, the ephemeral HOME and process-group cleanup still apply.
* **Everything is audited** with an explicit ``shell.exec`` event carrying the
  command, cwd, exit code, duration and bytes. The writer redacts named
  credential fields, so a ``password=...`` in the command does not become
  plaintext audit data.
* **The full output is an artifact** (sha256 included); the model only reads a
  bounded summary of ``<= 60`` lines plus the artifact reference. This is the
  token-budget contract of the plan: observations never paste 10 MB back.
* **A detached job returns at once** (V1-51): a command that asks for ``&`` or
  starts with ``nohup`` is launched with ``setsid``, its stdio redirected to a
  workspace log, and the observation carries the PID and the log path instead of
  the (never arriving) output. The OCI sandbox refuses it explicitly: an
  ephemeral container cannot keep the job alive.
* **A lexical deny list** (``NEXUS_SHELL_DENY`` can extend it) blocks the
  obviously destructive local commands. It is a guard-rail, not a security
  boundary: an arbitrary argv cannot be validated against the engagement
  scope. The compensating controls are the signed engagement, the confined
  workspace and the audit chain.
* **Fetch destinations are validated against the signed scope.** An arbitrary
  argv cannot be validated, but the destination of ``curl``/``wget``/``nc``
  can: the command is split into simple commands and the first argument of each
  client is checked with the same :class:`ScopeValidator` ``nexus.web.request``
  uses. Before this, ``curl https://bit.ly/...`` ran unchecked while the same
  URL through ``web.request`` aborted the run (measured in
  blackbox-10.67.183.218, 2026-10-19); the policy depended on which tool the
  model happened to pick.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
import time
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.fact_verification import sshpass_channels
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import OCISandbox, sandbox_for_environment
from nexus_core.kernel.scope_loader import scope_signing_secret
from nexus_core.kernel.sessions import validate_session_scope
from nexus_core.scope import ScopeValidator, ScopeViolation
from ._exec import run_in_sandbox
from .report_generate import default_artifact_root
from .workspace import workspace_root

#: Programs the sandbox is allowed to start. ``bash``/``sh`` are the only
#: entry points: everything the command itself launches is its own argv.
SHELL_ALLOWED_PROGRAMS: tuple[str, ...] = ("bash", "sh")

#: Hard caps from the plan (WP1): 10 MB of output, 900 s, 64 KiB of stdin.
SHELL_MAX_OUTPUT_BYTES = 10_000_000
SHELL_MAX_STDIN_BYTES = 65_536
SHELL_MIN_TIMEOUT_SECONDS = 5
SHELL_MAX_TIMEOUT_SECONDS = 900

#: The model never receives more than this many lines of an observation.
SHELL_SUMMARY_LINES = 60

#: Workspace directory that holds the logs of detached commands. The model can
#: read them with ``cat``/``tail`` (they are relative to its workspace).
BACKGROUND_LOG_DIRNAME = ".shell-background"

#: How long the *launch* of a detached command may take. Backgrounding exists so
#: the agent does not wait for the job; the launch itself still has to answer,
#: and a wrapper that cannot start is a determinate failure instead of a timeout.
BACKGROUND_LAUNCH_TIMEOUT_SECONDS = 10

#: A ``nohup`` in command position (not the word inside a quoted argument).
_NO_HUP_RE = re.compile(
    r"(?:^|[;&|(\n])\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*nohup\s"
)

#: The PID the launch wrapper echoes back (the only output it is read for).
_BACKGROUND_PID_RE = re.compile(r"NEXUS_BG_PID=(\d+)")


def shell_code(command: str) -> str:
    """*command* with the quoted regions and escapes blanked out.

    Operator detection must not be fooled by ``echo 'a & b'`` or by a flag with
    ``&`` inside: the grammar only exists outside quotes, so the scan runs over
    this projection while the original text is what gets executed.
    """
    out: list[str] = []
    quote = ""
    escaped = False
    for char in str(command or ""):
        if escaped:
            escaped = False
            out.append(" ")
            continue
        if char == "\\" and quote != "'":
            escaped = True
            out.append(" ")
            continue
        if quote:
            if char == quote:
                quote = ""
            out.append(" ")
            continue
        if char in "\"'":
            quote = char
            out.append(" ")
            continue
        out.append(char)
    return "".join(out)


def has_background_operator(command: str) -> bool:
    """Whether the command ends a list with ``&`` (not ``&&``, ``&>`` or ``>&``)."""
    code = shell_code(command)
    for index, char in enumerate(code):
        if char != "&":
            continue
        previous = code[index - 1] if index else ""
        following = code[index + 1] if index + 1 < len(code) else ""
        if following in {"&", ">"} or previous in {"&", ">"}:
            # ``&&`` (both members), ``&>file`` and ``2>&1`` are not background
            # operators: skipping both members is what keeps ``cmd && next``
            # on the foreground path.
            continue
        return True
    return False


def is_background_command(command: str) -> bool:
    """Whether *command* asks for a detached job (V1-51).

    Measured in Simple CTF (2026-10-18): the agent wrote
    ``nohup python ... &`` inside ``nexus.shell.exec`` to keep a job running
    while it did something else, the child inherited the handler's stdout pipe,
    and the call blocked until the 60 s timeout -two turns and a chunk of budget
    burned on a process that had already started. ``nohup`` without a redirect
    has the same effect: ``nohup`` only redirects when stdout is a terminal.
    """
    return has_background_operator(command) or bool(_NO_HUP_RE.search(shell_code(command)))


def background_body(command: str) -> str:
    """*command* without the trailing ``&`` the wrapper supplies itself."""
    text = str(command or "").rstrip()
    code = shell_code(text).rstrip()
    if code.endswith("&") and not code.endswith("&&"):
        index = len(code) - 1
        text = (text[:index] + text[index + 1 :]).rstrip()
    return text


def background_script(command: str, log_path: str) -> str:
    """Shell wrapper that detaches *command*, redirects it and echoes its PID.

    ``setsid`` puts the child in its own session so the sandbox's process-group
    cleanup cannot take it down with the launch wrapper. ``</dev/null`` and the
    log redirect are what actually remove the hang: a detached child that still
    holds the handler's stdout/stderr pipe keeps the call blocked even though
    the shell exited. ``$!`` is the PID to report back to the model.
    """
    body = background_body(command)
    return (
        f"setsid sh -c {shlex.quote(body)} </dev/null "
        f">{shlex.quote(log_path)} 2>&1 & echo NEXUS_BG_PID=$!"
    )


def background_log_path(root: str | Path, run_id: str) -> Path:
    """Workspace-relative log of one detached command (created lazily)."""
    base = Path(root) / BACKGROUND_LOG_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    stamp = re.sub(r"[^A-Za-z0-9_-]", "", str(run_id or "run"))[:32] or "run"
    return base / f"{stamp}-{int(time.time() * 1000)}.log"

#: Local guard-rail patterns; ``NEXUS_SHELL_DENY`` can only add more.
_DENY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        # Local privilege changes are not part of a remote engagement and the
        # sandbox has no password channel (the plan's "sin sudo" mitigation).
        r"(?:^|[;&|]\s*)(?:sudo|doas)\b",
        r"(?:^|[;&|]\s*)su\s",
        # Recursive deletion of the workspace root or the host root.
        r"\brm\s+(?:-[A-Za-z]*[rf][A-Za-z]*\s+)+(?:/|/\*|~|\$HOME)(?:\s|$|;)",
        r"\bfind\s+/(?:\s|$).*-delete\b",
        # Raw device writes and filesystem formatting.
        r"\bmkfs(?:\.\w+)?\b",
        r"\bdd\b[^\n;|]*\bof=/dev/(?:sd|nvme|vd|hd)",
        r">\s*/dev/(?:sd|nvme|vd|hd)",
        # Host power management.
        r"(?:^|[;&|]\s*)(?:shutdown|reboot|poweroff|halt)\b",
        # Classic fork bomb.
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        # Blanket permissions on the host root.
        r"\bchmod\s+-R\s+777\s+/(?:\s|$|;)",
    )
)


class ShellExecRequest(BaseModel):
    """Strict contract of the universal shell."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    command: str = Field(min_length=1, max_length=8192)
    cwd: str = Field(default=".", max_length=4096)
    timeout_seconds: int = Field(
        default=60,
        ge=SHELL_MIN_TIMEOUT_SECONDS,
        le=SHELL_MAX_TIMEOUT_SECONDS,
    )
    stdin: str | None = Field(default=None, max_length=SHELL_MAX_STDIN_BYTES)


def shell_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable definition of ``nexus.shell.exec``."""
    return ToolDefinition(
        tool_id="nexus.shell.exec",
        tenant_id=tenant_id,
        name="Universal shell",
        description=(
            "Ejecuta comandos shell en el sandbox y archiva la salida. El comando "
            "corre en el workspace del engagement: escribe archivos con rutas "
            "relativas (p. ej. workspace o ./loot.txt), no con rutas absolutas del host."
        ),
        input_schema=ShellExecRequest.model_json_schema(),
        risk=RiskLevel.HIGH,
        effect="execution",
        scope_required=True,
        sandbox_required=True,
        timeout_seconds=SHELL_MAX_TIMEOUT_SECONDS + 60,
        max_output_bytes=SHELL_MAX_OUTPUT_BYTES,
        required_permissions=["execute:tool:nexus.shell.exec"],
    )


def prohibited_reason(command: str) -> str | None:
    """Return the deny-list rule a command matches, or ``None``.

    ``NEXUS_SHELL_DENY`` appends operator rules separated by ``;;`` so a regex
    can contain ``|`` without ambiguity. Additional rules can only *widen* the
    guard-rail, never remove a built-in one.
    """
    extra = os.getenv("NEXUS_SHELL_DENY", "")
    patterns = list(_DENY_PATTERNS)
    for raw in extra.split(";;"):
        text = raw.strip()
        if not text:
            continue
        with suppress(re.error):
            patterns.append(re.compile(text, re.IGNORECASE))
    for pattern in patterns:
        if pattern.search(command):
            return pattern.pattern
    return None


#: The package-manager call the agent reaches for when a tool is missing. The
#: sandbox is unprivileged on purpose, so the call can only fail; the handler
#: turns that failure into a usable observation instead of a dead end.
_APT_INSTALL_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:apt-get|apt)\s+(?:-\S+\s+)*install\b",
    re.IGNORECASE,
)

#: Guidance the model gets when the package manager was refused by permissions.
APT_INSTALL_DENIED_GUIDANCE = (
    "No puedo instalar paquetes. Usa el binario si ya está, o busca una "
    "alternativa (ej. strings, exiftool, python3)."
)


def apt_install_permission_denied(
    command: str, stdout: str, stderr: str, exit_code: int | None
) -> bool:
    """Whether *command* was an ``apt`` install the OS refused for permissions.

    Only the measured shape triggers: the command starts with ``apt-get install``
    or ``apt install``, it exited non-zero, and the output carries the package
    manager's ``Permission denied``. A successful install, or any other command
    whose output happens to mention that phrase, keeps its normal outcome.
    """
    if exit_code is None or exit_code == 0:
        return False
    if not _APT_INSTALL_RE.match(str(command or "")):
        return False
    output = f"{stdout or ''}\n{stderr or ''}".lower()
    return "permission denied" in output


#: Clients whose destination is extractable from the command line. The shell
#: runs an arbitrary argv, so this is the only egress boundary that can be
#: enforced without turning the universal shell into a parser of every tool.
_SCOPE_CLIENTS: frozenset[str] = frozenset({"curl", "wget", "nc", "ncat", "netcat"})

#: Shell list separators: the end of one simple command.
_SIMPLE_COMMAND_SEPARATORS = ";&|\n"

_URL_TARGET_RE = re.compile(r"^https?://", re.IGNORECASE)
_IPV4_TARGET_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOST_PORT_TARGET_RE = re.compile(r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*):(?P<port>\d{1,5})$")
_BARE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Short options of ``curl``/``wget`` that consume the next token, so a file
#: name or a header never becomes a destination.
_CURL_VALUE_OPTIONS: frozenset[str] = frozenset(
    {
        "-o", "-H", "-d", "-X", "-u", "-A", "-e", "-b", "-c", "-F", "-T",
        "-x", "-m", "-w", "-r", "-K", "-E", "-Q", "-Y", "-y", "-z", "-C",
        "-D", "-U", "-P", "-t",
    }
)
_WGET_VALUE_OPTIONS: frozenset[str] = frozenset(
    {
        "-O", "-o", "-a", "-P", "-e", "-t", "-T", "-w", "-U", "-Q", "-l",
        "-A", "-R", "-D", "-I", "-X", "-B",
    }
)

#: Long options that consume the next token (``--opt=value`` is one token).
_FETCH_LONG_VALUE_OPTIONS: frozenset[str] = frozenset(
    {
        "--output", "--output-document", "--directory-prefix",
        "--append-output", "--header", "--data", "--data-raw",
        "--data-binary", "--request", "--user", "--user-agent", "--referer",
        "--cookie", "--cookie-jar", "--form", "--upload-file", "--proxy",
        "--max-time", "--connect-timeout", "--retry", "--config",
        "--write-out", "--resolve", "--cacert", "--cert", "--key",
        "--limit-rate", "--range", "--execute", "--tries", "--timeout",
        "--wait", "--post-data", "--method", "--ca-certificate",
        "--password",
    }
)

#: ``nc`` options that consume the next token as their value.
_NC_VALUE_OPTIONS: frozenset[str] = frozenset(
    {
        "-p", "-s", "-w", "-i", "-e", "-c", "-x", "-X", "-P", "-q",
        "-I", "-O", "-T", "-V", "-m", "-o", "-b", "-D", "-L", "-S",
        "-g", "-G",
    }
)

#: What the model reads when the command was aimed outside the engagement.
SHELL_SCOPE_DENIED_GUIDANCE = (
    "El objetivo {target} está fuera del alcance firmado. Ignora esa URL y "
    "busca otra ruta dentro del engagement; el comando no se ha ejecutado."
)


def _command_segments(command: str) -> list[str]:
    """Split *command* into simple commands, honouring quotes and escapes.

    ``echo 'a; b'`` is one command, ``curl x; nc y z`` is two. Only the first
    word of a segment is considered a client, so ``grep curl log`` is never
    mistaken for a ``curl`` call.
    """
    segments: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    for char in str(command or ""):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char in _SIMPLE_COMMAND_SEPARATORS:
            segments.append("".join(current))
            current = []
            continue
        current.append(char)
    segments.append("".join(current))
    return [segment for segment in (part.strip() for part in segments) if segment]


def _segment_tokens(segment: str) -> list[str]:
    """Tokens of one simple command; a quoting error falls back to ``split``."""
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _positional_arguments(client: str, arguments: list[str]) -> list[str]:
    """Positional arguments of a ``curl``/``wget`` call.

    Options and the token they consume are skipped, so ``-o header.jpg`` or
    ``-H 'Host: x'`` never lands here. ``--url`` is the exception: its value
    *is* the destination.
    """
    value_options = _CURL_VALUE_OPTIONS if client == "curl" else _WGET_VALUE_OPTIONS
    positionals: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            positionals.extend(arguments[index + 1 :])
            break
        if token.startswith("--"):
            if token.startswith("--url="):
                positionals.append(token[len("--url="):])
                index += 1
            elif token == "--url":
                if index + 1 < len(arguments):
                    positionals.append(arguments[index + 1])
                index += 2
            elif "=" in token:
                index += 1
            else:
                index += 2 if token in _FETCH_LONG_VALUE_OPTIONS else 1
            continue
        if token.startswith("-") and len(token) > 1:
            index += 2 if token in value_options else 1
            continue
        positionals.append(token)
        index += 1
    return positionals


def _fetch_argument_target(argument: str) -> str | None:
    """Destination named by one positional ``curl``/``wget`` argument.

    ``curl`` and ``wget`` treat a positional argument as a URL with or without
    a scheme, so ``bit.ly/x`` is as much a destination as ``https://bit.ly/x``.
    A local path (``/tmp/x``), stdin (``-``) or a bare word without a dot
    (``stdin``, a port number) is not.
    """
    value = str(argument or "").strip()
    if not value or value == "-":
        return None
    if value.startswith(("/", "./", "../", "~")):
        return None
    if _URL_TARGET_RE.match(value):
        return value
    if _IPV4_TARGET_RE.match(value):
        return value
    authority = re.split(r"[/?#]", value, maxsplit=1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    match = _HOST_PORT_TARGET_RE.match(authority)
    if match:
        return match.group("host")
    if _BARE_HOST_RE.match(authority) and (
        "." in authority or authority.lower() == "localhost"
    ):
        return authority
    return None


def _nc_target(arguments: list[str]) -> str | None:
    """Host ``nc``/``ncat`` connects to (``None`` for a listener or a bare port).

    ``nc -lvnp 4444`` is a listener: the number is its port, not a host. The
    first positional token is the destination, which may be a hostname.
    """
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            index += 1
            break
        if token.startswith("-") and len(token) > 1:
            index += 2 if token in _NC_VALUE_OPTIONS else 1
            continue
        break
    if index >= len(arguments):
        return None
    host = arguments[index].strip()
    if not host or host.isdigit():
        return None
    if _URL_TARGET_RE.match(host):
        return host
    match = _HOST_PORT_TARGET_RE.match(host)
    if match:
        return match.group("host")
    if _BARE_HOST_RE.match(host):
        return host
    return None


def fetch_targets(command: str) -> list[str]:
    """Destinations a ``curl``/``wget``/``nc`` command in *command* reaches.

    Reads the command the way the shell will: one simple command per segment,
    ``VAR=value`` assignments skipped, and the client may be an absolute path
    (``/usr/bin/curl``). Returns them in order, without duplicates.
    """
    targets: list[str] = []
    for segment in _command_segments(command):
        tokens = _segment_tokens(segment)
        while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
            tokens.pop(0)
        if not tokens:
            continue
        client = os.path.basename(tokens[0]).lower()
        if client not in _SCOPE_CLIENTS:
            continue
        arguments = tokens[1:]
        if client in {"curl", "wget"}:
            for argument in _positional_arguments(client, arguments):
                target = _fetch_argument_target(argument)
                if target and target not in targets:
                    targets.append(target)
        else:
            target = _nc_target(arguments)
            if target and target not in targets:
                targets.append(target)
    return targets


def _target_host(target: str) -> str:
    """Host part of a target (URL or bare host), lowercase, no brackets."""
    text = str(target or "").strip()
    if _URL_TARGET_RE.match(text):
        try:
            return str(urlsplit(text).hostname or "").strip("[]")
        except ValueError:
            return ""
    return text.strip("[]")


def _is_loopback_host(host: str) -> bool:
    """Whether *host* never leaves the machine.

    Loopback is not an engagement target: a local callback the agent started
    itself (``curl http://127.0.0.1:8080``) must not be reported as a scope
    violation, or the guard would break local tooling without protecting
    anything.
    """
    text = str(host or "").strip().strip("[]").split("%", 1)[0].lower()
    if not text:
        return False
    if text in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def out_of_scope_fetch_target(command: str, scope: Any) -> ScopeViolation | None:
    """First fetch destination *command* names that the signed scope rejects.

    ``None`` means "nothing to check or everything in scope". The validator is
    the same one ``nexus.web.request`` uses, so both channels now answer the
    same question with the same rules (measured in blackbox-10.67.183.218:
    ``web.request`` blocked ``bit.ly`` and ``shell.exec`` did not).
    """
    if scope is None:
        return None
    targets = fetch_targets(command)
    if not targets:
        return None
    validator = ScopeValidator(scope, signing_secret=scope_signing_secret())
    for target in targets:
        if _is_loopback_host(_target_host(target)):
            continue
        try:
            validator.validate(target)
        except ScopeViolation as exc:
            return exc
    return None


def resolve_cwd(root: str | Path, cwd: str) -> tuple[str, str]:
    """Resolve the model's relative ``cwd`` inside the workspace.

    Returns ``(absolute, relative)``; the relative form is what the sandbox
    receives and what the audit records. ``..``, absolute paths, symlinks that
    escape and non-directories are refused.
    """
    root_path = Path(root).resolve()
    text = str(cwd or ".").strip() or "."
    candidate = Path(text)
    if candidate.is_absolute():
        raise ValueError("cwd must be relative to the engagement workspace")
    resolved = (root_path / candidate).resolve()
    if resolved != root_path and root_path not in resolved.parents:
        raise ValueError("cwd escapes the engagement workspace")
    if not resolved.is_dir():
        raise ValueError("cwd is not a directory in the engagement workspace")
    return str(resolved), str(resolved.relative_to(root_path))


def summarize(stdout: str, stderr: str, *, limit: int = SHELL_SUMMARY_LINES) -> str:
    """Return at most ``limit`` lines of output (head + tail when truncated)."""
    text = stdout
    if stderr:
        text = f"{stdout}\n[stderr]\n{stderr}" if stdout else f"[stderr]\n{stderr}"
    lines = text.splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    head = (limit + 1) // 2
    tail = limit - head
    omitted = len(lines) - limit
    return "\n".join(
        [*lines[:head], f"… ({omitted} lines omitted; see artifact) …", *lines[-tail:]]
    )


def _combined_output(
    command: str, stdout: str, stderr: str, exit_code: int | None, timed_out: bool
) -> bytes:
    """Build the artifact payload: the full, unabridged stdout+stderr."""
    parts = [f"$ {command}\n", stdout]
    if stderr:
        parts.extend(("\n[stderr]\n", stderr))
    parts.append(f"\n[exit={exit_code} timed_out={timed_out}]\n")
    data = "".join(parts).encode("utf-8", errors="replace")
    if len(data) > SHELL_MAX_OUTPUT_BYTES:
        data = data[:SHELL_MAX_OUTPUT_BYTES] + b"\n[artifact truncated at 10 MB]\n"
    return data


#: One in-flight shell command per run. The plan's limit is one concurrent
#: process per session; this serializes the handler inside a process (the
#: durable job/task layer already serializes across workers).
_RUN_LOCKS: dict[str, asyncio.Lock] = {}


def _run_lock(run_id: str) -> asyncio.Lock:
    lock = _RUN_LOCKS.get(run_id)
    if lock is None:
        lock = _RUN_LOCKS.setdefault(run_id, asyncio.Lock())
    return lock


def _audit(
    context: RunContext,
    *,
    command: str,
    cwd: str,
    exit_code: int | None,
    duration_ms: int,
    bytes_written: int,
    timed_out: bool,
    decision: str = "allow",
    reason: str | None = None,
) -> None:
    """Append the mandatory ``shell.exec`` audit event (best effort on no store)."""
    if context.store is None:
        return
    payload: dict[str, Any] = {
        "command": command,
        "cwd": cwd,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "bytes": bytes_written,
        "timed_out": timed_out,
        "run_id": context.run_id,
    }
    if reason:
        payload["reason"] = reason
    AuditWriter(context.store).append(
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
        actor_id=context.identity.subject_id,
        action="shell.exec",
        resource_type="process",
        resource_id=context.run_id,
        payload=payload,
        decision=decision,
    )


async def _launch_background(
    request: ShellExecRequest,
    context: RunContext,
    sandbox: Any,
    program: str,
    cwd_relative: str,
    root: Path,
    started: float,
) -> ToolResult:
    """Start *request.command* detached and return at once with its PID (V1-51).

    The answer is not "the command finished": it is "the process exists". The
    model gets the PID, the log it writes and a pointer to read it, which is what
    lets it run ``sqlmap``/``hydra`` in the background and keep enumerating; the
    launch is audited like any other ``shell.exec`` with ``reason=background``.
    """
    if isinstance(sandbox, OCISandbox):
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason="background_not_supported_in_oci",
        )
        return ToolResult(
            output={
                "error": "background execution is not available in the OCI sandbox",
                "command": request.command,
                "guidance": (
                    "El contenedor OCI es efímero: un proceso en segundo plano muere "
                    "con él. Ejecuta el comando en primer plano con un "
                    "timeout_seconds mayor, o divídelo en pasos más cortos."
                ),
            },
            verified=False,
            outcome="unavailable",
            verification_method="shell_background_unavailable",
            evidence={"background": False, "cwd": cwd_relative},
        )
    log_file = background_log_path(root, context.run_id)
    log_relative = str(log_file.relative_to(Path(root).resolve()))
    script = background_script(request.command, str(log_file))
    try:
        async with _run_lock(context.run_id):
            launch = await run_in_sandbox(
                sandbox,
                [program, "-lc", script],
                timeout_seconds=min(request.timeout_seconds, BACKGROUND_LAUNCH_TIMEOUT_SECONDS),
                image_env="NEXUS_SHELL_IMAGE",
                default_image="python:3.12-alpine",
            )
    except (FileNotFoundError, PermissionError) as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason=type(exc).__name__,
        )
        return ToolResult(
            output={"error": f"shell unavailable: {type(exc).__name__}", "cwd": cwd_relative},
            verified=False,
            outcome="unavailable",
            verification_method="shell_unavailable",
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    match = _BACKGROUND_PID_RE.search(launch.stdout or "")
    pid = int(match.group(1)) if match else None
    content = _combined_output(
        request.command, launch.stdout, launch.stderr, launch.exit_code, launch.timed_out
    )
    artifact = configured_artifact_store(context.store, default_artifact_root()).put(
        context.tenant_id,
        content,
        "text/plain; charset=utf-8",
        run_id=context.run_id,
        metadata={
            "engagement_id": context.engagement_id,
            "kind": "shell-background-launch",
            "pid": pid,
            "log": log_relative,
        },
    )
    launched = pid is not None and launch.exit_code == 0 and not launch.timed_out
    _audit(
        context, command=request.command, cwd=cwd_relative,
        exit_code=launch.exit_code, duration_ms=duration_ms,
        bytes_written=len(content), timed_out=launch.timed_out,
        reason="background" if launched else "background_launch_failed",
    )
    summary = (
        f"Comando lanzado en segundo plano (PID {pid}). Sigue con otra tarea y "
        f"lee su salida con `tail -n 40 {log_relative}` cuando la necesites."
        if launched
        else "No se pudo lanzar el comando en segundo plano; revisa la salida del wrapper."
    )
    return ToolResult(
        output={
            "background": True,
            "launched": launched,
            "pid": pid,
            "log": log_relative,
            "command": request.command,
            "summary": summary,
            "artifact": artifact,
            "artifact_ref": artifact.get("id"),
            "sha256": artifact.get("sha256"),
            "exit_code": launch.exit_code,
            "timed_out": launch.timed_out,
            "duration_ms": duration_ms,
            "cwd": cwd_relative,
        },
        verified=launched,
        outcome="" if launched else ("timeout" if launch.timed_out else "error"),
        verification_method=(
            "shell_background_launched" if launched else "shell_background_not_started"
        ),
        evidence={
            "background": True,
            "pid": pid,
            "log": log_relative,
            "cwd": cwd_relative,
            "sha256": artifact.get("sha256"),
            "artifact_ref": artifact.get("id"),
        },
        exit_code=launch.exit_code,
        stdout=summary,
        stderr="",
        timed_out=launch.timed_out,
    )


async def shell_exec_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Run one sandboxed command, archive its output and return a summary."""
    request = ShellExecRequest.model_validate(arguments)
    validate_session_scope(context)
    root = workspace_root()
    _, cwd_relative = resolve_cwd(root, request.cwd)
    started = time.monotonic()

    reason = prohibited_reason(request.command)
    if reason is not None:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason=reason,
        )
        return ToolResult(
            output={
                "error": "command refused by the local shell deny list",
                "rule": reason,
                "command": request.command,
                "guidance": (
                    "Reformula sin privilegios locales ni operaciones destructivas; "
                    "el comando no se ha ejecutado."
                ),
            },
            verified=False,
            outcome="denied",
            verification_method="shell_command_denied",
            evidence={"cwd": cwd_relative, "deny_rule": reason},
        )

    violation = out_of_scope_fetch_target(request.command, context.scope)
    if violation is not None:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason="shell_scope_denied",
        )
        return ToolResult(
            output={
                "error": f"ScopeViolation({violation.target}): {violation.reason}",
                "command": request.command,
                "target": violation.target,
                "guidance": SHELL_SCOPE_DENIED_GUIDANCE.format(
                    target=violation.target
                ),
            },
            verified=False,
            outcome="scope_denied",
            verification_method="shell_scope_denied",
            evidence={"cwd": cwd_relative, "target": violation.target},
        )

    stdin_data = request.stdin.encode("utf-8") if request.stdin is not None else None
    if stdin_data is not None and len(stdin_data) > SHELL_MAX_STDIN_BYTES:
        raise ValueError("stdin exceeds the local shell limit")

    sandbox = sandbox_for_environment(root, allowed_programs=SHELL_ALLOWED_PROGRAMS)
    # The plan's 10 MB ceiling is per shell invocation, not the 1 MB default of
    # the shared recon sandbox. Both LocalSandbox and OCISandbox expose it.
    with suppress(AttributeError):
        sandbox.max_output_bytes = SHELL_MAX_OUTPUT_BYTES
    program = "sh" if isinstance(sandbox, OCISandbox) else "bash"
    if is_background_command(request.command):
        # ``nohup ... &`` used to block until the timeout: the detached child
        # inherited the handler's pipes. A background request is answered at
        # once with the PID instead of waited for (V1-51).
        return await _launch_background(
            request, context, sandbox, program, cwd_relative, root, started
        )
    try:
        async with _run_lock(context.run_id):
            result = await run_in_sandbox(
                sandbox,
                [program, "-lc", request.command],
                timeout_seconds=request.timeout_seconds,
                image_env="NEXUS_SHELL_IMAGE",
                default_image="python:3.12-alpine",
                input_data=stdin_data,
            )
    except (FileNotFoundError, PermissionError) as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason=type(exc).__name__,
        )
        return ToolResult(
            output={"error": f"shell unavailable: {type(exc).__name__}", "cwd": cwd_relative},
            verified=False,
            outcome="unavailable",
            verification_method="shell_unavailable",
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    content = _combined_output(
        request.command, result.stdout, result.stderr, result.exit_code, result.timed_out
    )
    artifact = configured_artifact_store(context.store, default_artifact_root()).put(
        context.tenant_id,
        content,
        "text/plain; charset=utf-8",
        run_id=context.run_id,
        metadata={
            "engagement_id": context.engagement_id,
            "kind": "shell-output",
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
        },
    )
    summary = summarize(result.stdout, result.stderr)
    if apt_install_permission_denied(
        request.command, result.stdout, result.stderr, result.exit_code
    ):
        # The tool exists, the command ran, and the OS refused the installation.
        # Reporting it as ``unavailable`` retires the route without pretending the
        # shell is broken, and the guidance names the local binaries that replace
        # the missing package (measured in blackbox-10.67.183.218: three failed
        # ``apt-get install steghide`` calls burned the turn budget).
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=result.exit_code, duration_ms=duration_ms,
            bytes_written=len(content), timed_out=result.timed_out,
            reason="apt_install_permission_denied",
        )
        return ToolResult(
            output={
                "error": "no permission to install packages",
                "command": request.command,
                "guidance": APT_INSTALL_DENIED_GUIDANCE,
                "summary": summary,
                "artifact": artifact,
                "artifact_ref": artifact.get("id"),
                "sha256": artifact.get("sha256"),
                "exit_code": result.exit_code,
                "cwd": cwd_relative,
            },
            verified=False,
            outcome="unavailable",
            verification_method="apt_install_permission_denied",
            evidence={
                "cwd": cwd_relative,
                "exit_code": result.exit_code,
                "artifact_ref": artifact.get("id"),
            },
            exit_code=result.exit_code,
            stdout=summary,
            stderr="",
            timed_out=False,
        )
    # An ``sshpass``-wrapped client is an authenticated channel, not an opaque
    # local process: the same login ``nexus.post.ssh_exec`` makes, started by the
    # generic shell. It is recorded here (target/user/port, never the secret) so
    # the run's evidence says which host this command really reached; the facts
    # are derived by ``kernel.fact_verification`` from the same parsed command.
    channels = sshpass_channels(request.command)
    _audit(
        context, command=request.command, cwd=cwd_relative,
        exit_code=result.exit_code, duration_ms=duration_ms,
        bytes_written=len(content), timed_out=result.timed_out,
    )
    verified = result.exit_code == 0 and not result.timed_out and not result.cancelled
    # A shell is a terminal, not a predicate: ``grep`` with no match exits 1,
    # ``test -f`` exits 1, a pipeline reports its last command. A non-zero exit
    # says the *command* failed, never that the tool is broken, so it is
    # reported as the determinate ``command_failed`` outcome with the real
    # output attached instead of raising "post-condition was not verified".
    # Measured in run_7661dda481784eebb17a76e037c5722b (2026-10-20): six
    # ``curl ... | grep`` probes that had answered correctly were discarded as
    # tool failures and the run died without ever seeing its own output.
    command_failed = (
        not verified and not result.timed_out and not result.cancelled
        and result.exit_code is not None
    )
    return ToolResult(
        output={
            "summary": summary,
            "artifact": artifact,
            "artifact_ref": artifact.get("id"),
            "sha256": artifact.get("sha256"),
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "duration_ms": duration_ms,
            "output_bytes": len(content),
            "stdout_lines": result.stdout.count("\n") + (1 if result.stdout else 0),
            "stderr_lines": result.stderr.count("\n") + (1 if result.stderr else 0),
            "cwd": cwd_relative,
            # Absolute sandbox root: the model can never guess it, and a guessed
            # absolute path (``/home/<user>/omni-agentcs/workspace/pass.txt`` in
            # run_1052d63f9bba4838902b3aa21bd27d21) made a write fail with a
            # cryptic exit-code post-condition error instead of "write here".
            "workspace": str(root),
        },
        verified=verified,
        outcome=(
            "timeout" if result.timed_out
            else "command_failed" if command_failed
            else ""
        ),
        verification_method="shell_exit_code",
        evidence={
            "cwd": cwd_relative,
            "workspace": str(root),
            "exit_code": result.exit_code,
            "duration_ms": duration_ms,
            "timed_out": result.timed_out,
            "sha256": artifact.get("sha256"),
            "artifact_ref": artifact.get("id"),
            **(
                {"ssh_channels": [channel.descriptor() for channel in channels]}
                if channels else {}
            ),
        },
        exit_code=result.exit_code,
        # The exit code travels in ``output`` and the capture in the artifact, so
        # the model reads what the command answered before deciding the next
        # step even when that answer was an error.
        stdout=summary,
        stderr="",
        timed_out=result.timed_out,
    )


__all__ = [
    "APT_INSTALL_DENIED_GUIDANCE",
    "BACKGROUND_LOG_DIRNAME",
    "SHELL_SCOPE_DENIED_GUIDANCE",
    "SHELL_ALLOWED_PROGRAMS",
    "SHELL_MAX_OUTPUT_BYTES",
    "SHELL_MAX_STDIN_BYTES",
    "SHELL_MAX_TIMEOUT_SECONDS",
    "SHELL_MIN_TIMEOUT_SECONDS",
    "SHELL_SUMMARY_LINES",
    "ShellExecRequest",
    "apt_install_permission_denied",
    "background_body",
    "background_log_path",
    "background_script",
    "fetch_targets",
    "has_background_operator",
    "is_background_command",
    "out_of_scope_fetch_target",
    "prohibited_reason",
    "resolve_cwd",
    "shell_code",
    "shell_exec_definition",
    "shell_exec_handler",
    "summarize",
]
