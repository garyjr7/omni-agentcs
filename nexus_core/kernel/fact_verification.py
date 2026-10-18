"""Trusted, narrow semantic parsers. Model/extension metadata is never promoted.

New parsers must establish the claimed post-condition, not merely successful
execution. Unsupported outputs remain inventory; they cannot advance phases.

Two invariants this module enforces on the facts it asserts (V1-29, V1-31):

* a ``credential`` fact never carries a plaintext secret. The value holds
  ``secret_ref`` -the handle of :mod:`nexus_core.kernel.secret_store`- and never a
  ``password``; when a handler still returns the plaintext (a tool not yet
  converted), the verifier stores it and asserts the reference, so the blackboard
  is uniformly reusable instead of uniformly unreadable.
* an ``access`` fact means a **proven channel**, not a validated password. A sweep
  that authenticated ``lin`` against ssh proves the password, not that anyone ran
  a command; measured in rerun 8, ``cred_bruteforce_completed`` asserted ``access``
  and the plan marked *Acceso inicial ✓* while no shell had ever existed.
"""
import re
import shlex
from typing import NamedTuple

from .blackboard import Blackboard, is_verified_fact

#: Flag-shaped tokens (``flag{fake_flag}``, ``flag{fake_flag}``, ``flag{fake_flag}``) found in the
#: output of a verified command execution. Keeping the prefixes explicit avoids
#: turning any brace-wrapped text into "loot".
FLAG_RE = re.compile(r"(?:THM|HTB|FLAG|flag|CTF|ctf)\{[^}\s\x00]{4,200}\}")

#: A single read of one file (``cat``, optionally behind ``sudo``). Only this
#: shape attributes the output to the file it came from: a pipe or a loop could
#: print anything, so it is not evidence about a path.
_FLAG_FILE_READ_RE = re.compile(
    r"^\s*(?:sudo\s+(?:-[A-Za-z]+\s+)*)?(?:cat|tac|less|more|type)\s+"
    r"(?P<path>\"[^\"]+\"|'[^']+'|[^\s|;&<>]+)\s*$",
    re.IGNORECASE,
)

#: Conventional CTF flag files (``user.txt``, ``root.txt``, ``flag.txt``,
#: ``flag1.txt``...). The *name* is what makes a verified read loot; Simple CTF
#: stores ``G00d j0b, keep up!`` in ``user.txt``, with no ``flag{fake_flag}`` shape, and
#: the engine used to record nothing because of it.
_FLAG_FILE_NAME_RE = re.compile(
    r"(?:^|/)(?:user|root|flag|proof|local|system)(?:[._-]?\d+)?\.txt$",
    re.IGNORECASE,
)

#: Longest file content promoted as loot; a longer line is not a flag and
#: truncating it would store a text that never existed on the target.
FLAG_FILE_TEXT_MAX = 500

#: ``verification_method`` of the facts a generic shell asserts when the command
#: it ran was an authenticated ``ssh`` (``sshpass``). The channel is proven -the
#: command really ran on the target- but by ``nexus.shell.exec`` rather than by
#: ``nexus.post.ssh_exec``, so the board can tell the two apart.
SHELLPASS_METHOD = "shell_sshpass_completed"

#: ``verification_method`` of the ``nexus.shell.exec`` result these facts come
#: from. ``shell_command_denied``/``shell_unavailable`` never get this far
#: (``ToolResult.success`` is false), so the check only pins the contract.
SHELL_RESULT_METHOD = "shell_exit_code"

#: The canonical root identity line (``uid=0(root) gid=0(root) groups=0(root)``).
#: It substantiates the claim on its own, whatever wrapper printed it: the same
#: line ``ssh_exec`` accepts (V1-35) is the same proof over ``sshpass``.
_ROOT_LINE_RE = re.compile(r"uid=0\(root\) gid=\d+")

#: Programs a ``sshpass`` wrapper can start that *are* the authenticated channel
#: of ``nexus.post.ssh_exec``; ``scp``/``rsync``/``sftp`` are not (they move files
#: and print no command output), so they never derive an ``access`` fact.
_SSH_PROGRAMS = frozenset({"ssh", "ssh.exe"})

#: Native-client options that consume the next token; anything else that starts
#: with ``-`` is a flag without a value (``-4``, ``-A``, ``-T``...).
_SSH_OPTION_WITH_VALUE = frozenset(
    "-B -b -c -D -E -e -F -I -i -J -L -m -O -o -Q -R -S -W -w".split()
)

#: Tokens a launcher can leave before the program it starts. A wrapper only at
#: *command position* is a program really being run; ``command -v sshpass`` or a
#: branch of ``if ...; then`` is not, and the shell's exit code then says nothing
#: about whether a login ever happened.
_COMMAND_POSITION_PRECEDERS = frozenset(
    {";", "&&", "||", "|", "&", "(", "{", "!", "env", "timeout", "nice",
     "nohup", "stdbuf", "xargs", "-oL", "-eL"}
)

#: ``VAR=value`` prefixing a command (``SSHPASS=x sshpass -e ssh ...``).
_SHELL_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")

#: A trailing redirection: the client's own (``... ssh host 'id' 2>&1``) or the
#: remote command's (``cat ~/user.txt 2>/dev/null``). It decides where the text
#: goes, not what was read, so it is not part of the command's shape.
_TRAILING_REDIRECTION_RE = re.compile(r"\s+(?:\d?>>?[^\s]+|\d?>&\d)\s*$")


def strip_redirections(command) -> str:
    """A remote command without its trailing shell redirections."""
    text = str(command or "").strip()
    while True:
        stripped = _TRAILING_REDIRECTION_RE.sub("", text).strip()
        if stripped == text:
            return text
        if not stripped:
            return ""
        text = stripped


def _at_command_position(tokens, index: int) -> bool:
    """Whether ``tokens[index]`` is a program the shell would actually start."""
    if index == 0:
        return True
    previous = tokens[index - 1]
    if previous in _COMMAND_POSITION_PRECEDERS:
        return True
    # ``id; sshpass ...`` splits as ``['id;', 'sshpass', ...]``: the separator is
    # glued to the previous word instead of standing alone.
    if previous.rstrip(";&|") != previous:
        return True
    if previous.isdigit() and index >= 2 and tokens[index - 2] in ("timeout", "nice"):
        return True
    return bool(_SHELL_ASSIGNMENT_RE.fullmatch(previous))


class SshChannel(NamedTuple):
    """One ``sshpass``-wrapped native client found inside a shell command.

    ``command`` is the remote command the client ran (``""`` when it opened an
    interactive session); ``password`` is the ``sshpass -p`` value, kept only to
    be stored in the vault -it never goes to the board (V1-29).
    """

    target: str
    username: str
    port: int | None
    password: str
    command: str

    def descriptor(self) -> dict:
        """Channel as recorded in a result's evidence (never the secret)."""
        return {"target": self.target, "username": self.username or None,
                "port": self.port, "command": self.command}


def _program_name(token: str) -> str:
    """Basename of an argv token, so ``/usr/bin/sshpass`` counts as ``sshpass``."""
    return str(token).rsplit("/", 1)[-1].lower()


def _sshpass_password(tokens, wrapper: int, client: int) -> str:
    """Value of ``sshpass -p <password>`` (``""`` for ``-e``/``-f``/``-d``)."""
    for position in range(wrapper + 1, client):
        token = tokens[position]
        if token == "-p" and position + 1 < client:
            return tokens[position + 1]
        if token.startswith("-p") and len(token) > 2:
            return token[2:]
    return ""


def _ssh_destination(tokens, start: int):
    """``(target, username, port, remote command)`` of an ``ssh`` argv.

    Reads the native client's own options (``-p PORT``/``-pPORT``, ``-l USER``,
    ``-o Port=PORT``) and stops at the first positional argument, which is the
    ``[user@]host`` every ``ssh`` invocation must carry. Everything after it is
    the remote command -``ssh`` hands the rest of the line to the target shell,
    so it is *not* parsed as local argv.
    """
    username = ""
    port: int | None = None
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in ("-p", "-l") and index + 1 < len(tokens):
            value = tokens[index + 1]
            if token == "-l":
                username = value
            else:
                port = int(value) if value.isdigit() else None
            index += 2
            continue
        if token.startswith("-p") and len(token) > 2 and token[2:].isdigit():
            port = int(token[2:])
            index += 1
            continue
        if token.startswith("-l") and len(token) > 2:
            username = token[2:]
            index += 1
            continue
        if token in _SSH_OPTION_WITH_VALUE and index + 1 < len(tokens):
            value = tokens[index + 1]
            if token == "-o" and value.lower().startswith("port="):
                configured = value.split("=", 1)[1]
                port = int(configured) if configured.isdigit() else None
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        break
    if index >= len(tokens):
        return "", username, port, ""
    destination = tokens[index]
    user, separator, host = destination.rpartition("@")
    if not separator:
        user, host = "", destination
    if not host:
        return "", username, port, ""
    remote = strip_redirections(" ".join(tokens[index + 1:]))
    return host, username or user, port, remote


def sshpass_channels(command) -> tuple[SshChannel, ...]:
    """Every ``sshpass ... ssh`` invocation inside *command*, in argv order.

    ``nexus.shell.exec`` runs arbitrary argv, so the escalation of a CTF room is
    routinely ``sshpass -p '<secret>' ssh -p 2222 user@host '<command>'``: a real
    authenticated channel that used to derive **nothing** (measured in the last
    Simple CTF run: 2/2 flags captured, ``objective_complete=false``, exit 1 on
    ``budget_exceeded`` because the board never held the ``privilege``/``loot``
    the run had already obtained). Detection is lexical on purpose: it claims
    nothing about success, only that this command *is* a native ssh login -the
    caller still requires exit code 0 before asserting a fact.

    Only the wrappers at *command position* count (start of the line, after a
    chain separator, behind ``timeout``/``env``/an assignment). An ``sshpass``
    word inside ``command -v sshpass`` or a branch of ``if ...; then`` is not a
    login, and the shell's exit code would then say nothing about the channel.
    """
    text = str(command or "")
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:  # unbalanced quote: the shell would have refused it too
        return ()
    channels: list[SshChannel] = []
    for index, token in enumerate(tokens):
        if _program_name(token) != "sshpass" or not _at_command_position(tokens, index):
            continue
        client = next(
            (position for position in range(index + 1, len(tokens))
             if _program_name(tokens[position]) in _SSH_PROGRAMS),
            None,
        )
        if client is None:
            continue
        target, username, port, remote = _ssh_destination(tokens, client + 1)
        if not target:
            continue
        channels.append(SshChannel(
            target=target, username=username, port=port,
            password=_sshpass_password(tokens, index, client), command=remote,
        ))
    return tuple(channels)


def shell_root_identity(command, stdout) -> bool:
    """Whether the output of *command* states the invoking account is ``root``.

    Same bar as the ``ssh_exec`` branch: the canonical ``uid=0(root) gid=<n>``
    line, or the literal answer of ``whoami``/``id -u``. A ``sudo -l`` line that
    merely grants ``(root) NOPASSWD:`` is a *capability*, not an identity, and is
    deliberately not promoted.
    """
    text = str(stdout or "")
    if _ROOT_LINE_RE.search(text):
        return True
    single = str(command or "").strip()
    if single == "whoami" and text.strip() == "root":
        return True
    return single == "id -u" and text.strip() == "0"


#: Lines the native client prints *around* the remote output. When the caller
#: folds stderr into stdout (``... 2>&1``) these land in front of the flag, and
#: the first line of a verified read would otherwise be a warning (measured in
#: the Simple CTF run: ``sshpass … ssh … 'id; hostname; cat ~/user.txt' 2>&1``
#: starts with ``Warning: Permanently added …``).
_SSH_CLIENT_NOISE_RE = re.compile(
    r"^(?:\*\* WARNING:|\*\* This session may|\*\* The server may|"
    r"Warning: Permanently added|Warning: Identity file|Pseudo-terminal will)"
)


def _shell_output(output, result) -> str:
    """Bounded stdout of a ``nexus.shell.exec`` result.

    The handler keeps the full output as an artifact and returns a summary of
    head+tail lines; the verifier reads exactly what the run itself saw, so a
    fact can never be asserted from text the model was not shown.
    """
    for value in (output.get("summary"), output.get("stdout"), result.stdout):
        if isinstance(value, str) and value.strip():
            return value
    return ""


def shell_read_text(command, summary) -> str:
    """Content printed by a single read of a flag file over the shell channel.

    :func:`flag_file_text` takes the first line of the output, which is right for
    ``ssh_exec`` (stdout reaches it clean). Here the summary is the *local* shell
    output, so the client's own diagnostics are removed first and the read must
    leave exactly one line -the shape a flag file has-, otherwise nothing is
    attributed to the path.
    """
    if not flag_file_path(command):
        return ""
    stdout = str(summary or "").split("\n[stderr]", 1)[0]
    lines = [line.strip() for line in stdout.splitlines()
             if line.strip() and not _SSH_CLIENT_NOISE_RE.match(line.strip())]
    if len(lines) != 1:
        return ""
    text = lines[0]
    if len(text) > FLAG_FILE_TEXT_MAX or any(ord(ch) < 0x20 for ch in text):
        return ""
    return text


#: ``verification_method`` of the facts an accepted MSF session asserts (V1-24).
#: Distinct from the handler's ``session_established``: that one is the *result's*
#: method, this one is the *fact's*, so the planner can tell a session this engine
#: proved (window + target) from any other ``session`` fact.
MSF_SESSION_METHOD = "msf_session_established"

#: ``verification_method`` of the msf_exploit result that owns a provenanced
#: session (the only one this module promotes).
_MSF_SESSION_RESULT_METHOD = "session_established"

#: Separator of MSF's canonical session descriptor, ``<USER> @ <HOST>``
#: (``NT AUTHORITY\SYSTEM @ WIN-JO6REVNMMMP``).
_SESSION_INFO_SEPARATOR = " @ "

#: Windows identity queries whose output states the *invoking* account's own
#: group membership. ``whoami; hostname`` deliberately does not match: the marker
#: must come from an identity query, not from whatever else shares the line.
_WIN_IDENTITY_RE = re.compile(r"^whoami(\s|$)", re.IGNORECASE)

#: Markers of an administrative Windows group. The well-known SIDs are the
#: reliable half (names are localized); a wrong answer would need the querying
#: account to be in one of these groups, which is exactly the claim.
_WIN_ADMIN_RE = re.compile(
    r"(BUILTIN\\Administrators|Domain Admins|Enterprise Admins|Schema Admins|"
    r"S-1-5-32-544|S-1-5-21-\d+-\d+-\d+-512|S-1-5-21-\d+-\d+-\d+-519)",
    re.IGNORECASE,
)

#: ``net (local)group <group> /domain`` — a listing of the accounts inside an
#: administrative group. Only the domain database is consulted: a local group on
#: a member host proves nothing about the domain.
_WIN_GROUP_QUERY_RE = re.compile(
    r"^\s*net\s+(?:localgroup|group)\s+(?P<group>\"[^\"]+\"|'[^']+'|[^\s]+)\s+[^|;]*/domain\b",
    re.IGNORECASE,
)

#: Group names that, when listed by ``net … /domain``, mean "domain-level admin".
_WIN_ADMIN_GROUPS = frozenset(
    {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administradores",
        "administrateurs",
        "administratoren",
    }
)

#: A single-token Windows account name, e.g. ``tom`` or ``WINDOMAIN\\tom``.
_WIN_ACCOUNT_RE = re.compile(r"^[^\s()]{1,64}$")

#: ``Get-Content <path>`` / ``type <path>`` / ``cat <path>`` reading exactly one
#: literal file: no pipes, no wildcards, no loops, no redirections. Only this
#: shape lets the verifier attribute a flag to the path that was read.
_WIN_READ_RE = re.compile(
    r"^\s*(?:get-content|gc|type|cat)\s+(?P<path>\"[^\"]+\"|'[^']+'|[^\s|;<>]+)\s*$",
    re.IGNORECASE,
)


def flag_file_path(command):
    """Path a command reads, when that command is a single read of a flag file."""
    match = _FLAG_FILE_READ_RE.match(str(command or ""))
    if not match:
        return ""
    path = match.group("path").strip("\"'")
    return path if _FLAG_FILE_NAME_RE.search(path) else ""


def flag_file_text(command, stdout):
    """Content of the flag file a verified read printed, or ``""``.

    One line, because that is what these files hold; a multi-line answer is a
    hint, an error or someone else's output, not a flag.
    """
    if not flag_file_path(command):
        return ""
    for line in str(stdout or "").splitlines():
        text = line.strip()
        if not text:
            continue
        if len(text) > FLAG_FILE_TEXT_MAX or any(ord(ch) < 0x20 for ch in text):
            return ""
        return text
    return ""


def _net_group_members(text):
    """Return the account rows of a ``net ... /domain`` group listing.

    Members live in the dashed block after ``Members``; the footer
    (``The command completed successfully.``) and anything after it are ignored.
    """
    members = []
    in_block = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            if in_block:
                break
            continue
        if len(line) >= 3 and set(line) <= {"-"}:
            in_block = True
            continue
        if not in_block:
            continue
        if line.lower().startswith("the command completed"):
            break
        account = line.lstrip("*").strip()
        if _WIN_ACCOUNT_RE.match(account):
            members.append(account)
    return members


def _secret_handle(value, *, kind="credential", tenant_id="system"):
    """Store a discovered plaintext and return its ``vault:<uuid>`` handle.

    Returns ``""`` when there is nothing to store or the vault is unwritable: a
    verification step must never abort a run, and a credential fact without a
    handle is still truthful (it just cannot be reused).
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        from .secret_store import default_secret_store

        return default_secret_store().put(text.encode("utf-8"), kind=kind, tenant_id=tenant_id)
    except Exception:  # noqa: BLE001 - the fact survives, the handle is dropped
        return ""


def _credential_handle(credential, *, kind="credential", tenant_id="system"):
    """Handle of one discovered credential: the handler's own ref, or a new one."""
    from .secret_store import is_secret_ref

    existing = str((credential or {}).get("secret_ref") or "")
    if is_secret_ref(existing):
        return existing
    return _secret_handle((credential or {}).get("password"), kind=kind, tenant_id=tenant_id)


def _proved_credential_handle(context, target, username):
    """Existing handle of a proved ``cred:ssh:<user>@<host>`` fact, or ``""``.

    The SSH channel is verified on *every* call, so without this lookup a long
    run would store the same password in the vault once per command. The fact is
    the registry: one handle per proved (user, host) pair, and the plaintext is
    written only the first time.
    """
    store = getattr(context, "store", None)
    engagement_id = str(getattr(context, "engagement_id", "") or "")
    if store is None or not engagement_id:
        return ""
    wanted = f"cred:ssh:{username}@{target}"
    try:
        facts = Blackboard(store).list_facts(
            getattr(context, "tenant_id", "system"), engagement_id, fact_type="credential"
        )
    except Exception:  # noqa: BLE001 - an unreadable board never breaks the run
        return ""
    for fact in facts:
        if not isinstance(fact, dict) or not is_verified_fact(fact):
            continue
        if str(fact.get("key") or "") != wanted:
            continue
        return str((fact.get("value") or {}).get("secret_ref") or "")
    return ""


def _session_owner(record):
    """Account named by an MSF session descriptor, or ``""`` when it names none.

    Only the canonical ``<USER> @ <HOST>`` shape counts. A record whose ``info``
    is a bare product word (``Meterpreter``) names no account, and an empty
    ``info`` -what msfrpcd answered when the session had just opened, measured in
    rerun 6- must never be read as a username.
    """
    if not isinstance(record, dict):
        return ""
    info = str(record.get("info") or "").strip()
    account, separator, _host = info.rpartition(_SESSION_INFO_SEPARATOR)
    if not separator:
        return ""
    return account.strip()


def _session_sid(result):
    """Numeric sid of the session, when the result exposes it.

    The sid is the ``session.list`` key; the handler's result carries the RPC
    ``job_id`` instead (a different number: 9 vs 2 in the measured run), so the
    key is read from the evidence when present and left null when not. Inventing
    it from the job id would be a lie about which session this is.
    """
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    sid = evidence.get("sid")
    return sid if isinstance(sid, int) and not isinstance(sid, bool) else None


#: ``verification_method`` values that prove the SSH channel reached the host
#: and ran the command. ``ssh_exec_sshpass_completed`` is Plan B (Simple CTF
#: runs 1 and 2): the same authenticated command, replayed with the native
#: client because the target refused the next paramiko session. It is as much a
#: real channel as the paramiko one, so it derives the same facts.
SSH_EXEC_CHANNEL_METHODS = ('ssh_exec_completed', 'ssh_exec_sshpass_completed')


def derive_assertions(tool_id, arguments, result, context):
    if not result.success or not context.invocation_id:
        return []
    output = result.output
    rows = []

    def add(kind, target, value, key=None, method=None):
        if not target:
            return
        rows.append(dict(fact_type=kind, target=str(target), key=str(key or target),
                         value=value, verified=True, asserted_by='verifier',
                         verification_method=method or result.verification_method,
                         invocation_id=context.invocation_id, run_id=context.run_id))

    if tool_id == 'nexus.recon.nmap' and result.verification_method == 'nmap_xml_parsed':
        for host in output.get('scan', {}).get('hosts', []):
            if host.get('state') != 'up':
                continue
            target = host.get('ip')
            add('host', target, {'state': 'up'})
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    add('service', target, port, f"{target}:{port.get('port')}:{port.get('protocol')}")
    elif tool_id == 'nexus.recon.httpx' and result.verification_method == 'httpx_jsonl_parsed':
        for probe in output.get('probes', []):
            if probe.get('status_code'):
                add('endpoint', probe.get('url'), probe)
    elif tool_id == 'nexus.recon.gobuster' and result.verification_method == 'gobuster_text_parsed':
        # The parser names the HTTP code ``status`` (its ``to_dict``), not
        # ``status_code``; reading the wrong key silently dropped every verified
        # hit, so a directory scan could never close ``enumeration`` and the plan
        # kept sending the run back to enumerate (measured in the Simple CTF run
        # of 2026-10-17: 11 hits, 0 assertions, 27 turns on the same phase).
        for hit in output.get('hits', []):
            if hit.get('status') or hit.get('status_code'):
                add('endpoint', hit.get('url') or output.get('target'), hit, hit.get('path'))
    elif tool_id == 'nexus.post.ssh_exec' and result.verification_method in SSH_EXEC_CHANNEL_METHODS:
        target = output.get('target')
        username = arguments.get('username')
        port = arguments.get('port')
        port = port if isinstance(port, int) and 0 < port < 65536 else None
        # The port rides with the access fact: it is the one an authenticated
        # session really used, so the handlers can complete a later call from the
        # board instead of falling back to 22 (Simple CTF runs on 2222).
        add('access', target, {'transport': 'ssh', 'username': username, 'port': port})
        # V1-29 continuity: the password that just authenticated goes to the
        # vault and the fact carries only its handle, so the next turn -and the
        # next tool- reuse it without the model retyping a secret. Measured in
        # the Simple CTF run of 2026-10-17 (23:16 UTC): its last three turns went
        # to retyping by hand a credential the board already proved, and the run
        # closed as a failure with the flag one command away.
        handle = _proved_credential_handle(context, target, username)
        if not handle and username:
            handle = _credential_handle(
                {'password': arguments.get('password')},
                kind='ssh',
                tenant_id=str(getattr(context, 'tenant_id', 'system')),
            )
        if handle and username:
            add('credential', target,
                {'username': username, 'secret_ref': handle, 'service': 'ssh', 'port': port},
                f'cred:ssh:{username}@{target}')
        command = output.get('command', '').strip()
        stdout = output.get('stdout', '').strip()
        if output.get('exit_status') == 0 and (
            (command == 'id' and re.fullmatch(r'uid=0\(root\) gid=\d+[^\n]*', stdout))
            or (command == 'id -u' and stdout == '0')
            or (command == 'whoami' and stdout == 'root')
            # The canonical root identity line substantiates the claim on its own,
            # whatever ran it: measured in rerun 10, the escalation was proven by
            # ``sudo /bin/tar … --checkpoint-action=exec=/usr/bin/id``, whose stdout
            # printed ``uid=0(root) gid=0(root) groups=0(root)``. Requiring the
            # literal command ``id`` meant the engine recorded **no** ``privilege``
            # fact at all, so `privilege_escalation` could never close and the
            # planner could not see that the objective had been reached (V1-35).
            or re.search(r'uid=0\(root\) gid=\d+', stdout)
        ):
            add('privilege', target, {'uid': 0, 'user': 'root'})
        # A flag-shaped token in the output of a verified authenticated command is
        # loot: the channel is proven, so the flag came from a command that really
        # ran on the host. Same contract as ``nexus.web.wp_exec`` (the Windows
        # channel stays stricter and only attributes a single literal file read).
        if output.get('exit_status') == 0:
            captured = FLAG_RE.findall(stdout)
            for flag in captured:
                add('loot', flag, {'flag': flag, 'command': command, 'service': 'ssh'}, flag)
            # A verified read of a conventional flag file is loot on its own
            # evidence: the SSH channel is proven (exit 0) and the path says what
            # the text is, so a room whose flags carry no prefix still registers
            # the capture. Measured in Simple CTF: `cat ~/user.txt` printed the
            # flag, nothing derived it, and the agent could not see it had won.
            path = flag_file_path(command)
            text = flag_file_text(command, stdout)
            if text and text not in captured:
                add('loot', text,
                    {'content': text, 'flag': text, 'command': command,
                     'path': path, 'service': 'ssh'},
                    f"ssh:file:{path}")
    elif (tool_id == 'nexus.shell.exec'
          and result.verification_method == SHELL_RESULT_METHOD):
        # WP1's generic shell can run the same authenticated client as
        # ``nexus.post.ssh_exec``. Until this branch existed the engine was blind
        # to that channel: the Simple CTF run of 2026-10-17 captured both flags,
        # escalated through ``sshpass`` and still closed with
        # ``objective_complete=false`` (no ``privilege``/``loot`` on the board), so
        # the budget exemption never applied and the run exited 1 on
        # ``budget_exceeded`` with the room already solved.
        #
        # Only exit 0 proves anything here (``derive_assertions`` already refuses
        # a result that is not ``success``, which for this handler means exit 0
        # and not timed out/cancelled); a wrong password exits 5 and derives
        # nothing.
        channels = sshpass_channels((arguments or {}).get('command'))
        exit_code = output.get('exit_code', result.exit_code)
        if channels and exit_code == 0:
            first = channels[0]
            tenant = str(getattr(context, 'tenant_id', 'system'))
            add('access', first.target,
                {'transport': 'ssh', 'username': first.username or None,
                 'port': first.port, 'via': 'shell.exec'},
                method=SHELLPASS_METHOD)
            # V1-29 continuity: the password that authenticated goes to the vault
            # and the fact carries only its handle, so the next turn -or the next
            # tool- reuses it instead of retyping the secret.
            handle = (_proved_credential_handle(context, first.target, first.username)
                      if first.username else '')
            if not handle and first.username:
                handle = _credential_handle({'password': first.password}, kind='ssh',
                                            tenant_id=tenant)
            if handle and first.username:
                add('credential', first.target,
                    {'username': first.username, 'secret_ref': handle,
                     'service': 'ssh', 'port': first.port},
                    f'cred:ssh:{first.username}@{first.target}',
                    method=SHELLPASS_METHOD)
            # Privilege and loot are attributed to *one* host: with several
            # different targets in the same command line the summary mixes their
            # output, so only the channel itself (already added) is provable.
            text = _shell_output(output, result)
            if all(channel.target == first.target for channel in channels):
                if shell_root_identity(first.command, text):
                    add('privilege', first.target,
                        {'uid': 0, 'user': 'root', 'via': 'shell.exec'},
                        method=SHELLPASS_METHOD)
                captured = FLAG_RE.findall(text)
                for flag in captured:
                    add('loot', flag,
                        {'flag': flag, 'command': first.command,
                         'service': 'ssh', 'via': 'shell.exec'}, flag,
                        method=SHELLPASS_METHOD)
                # A single read of a conventional flag file is loot on the path
                # alone (Simple CTF's ``root.txt`` says "W3ll d0n3...", with no
                # prefix). A *chain* is not: the summary then mixes several
                # commands and nothing attributes a line to the file that was
                # read, so only flag-shaped tokens promote there.
                path = flag_file_path(first.command)
                content = shell_read_text(first.command, text) if path else ''
                if content and content not in captured:
                    add('loot', content,
                        {'content': content, 'flag': content,
                         'command': first.command, 'path': path,
                         'service': 'ssh', 'via': 'shell.exec'},
                        f'ssh:file:{path}', method=SHELLPASS_METHOD)
    elif tool_id == 'nexus.pwn.ret2libc' and result.verification_method == 'ret2libc_root_command':
        target = output.get('target')
        add('privilege', target, {'uid': 0, 'user': 'root'})
        flag = output.get('flag')
        if flag:
            add('loot', flag, {'flag': flag, 'libc_base': output.get('libc_base')}, flag)
    elif tool_id == 'nexus.web.wp_enum' and result.verification_method == 'wp_enum_completed':
        findings = output.get('findings') or {}
        url = output.get('url')
        if findings.get('version'):
            add('web_app', url, {'product': 'wordpress', 'version': findings['version'],
                                 'source': findings.get('version_source')})
        for user in findings.get('users') or ():
            slug = user.get('slug')
            if slug:
                add('user', slug, {'username': slug, 'id': user.get('id'),
                                   'service': 'wordpress'}, f'wp:{slug}')
        for entry in findings.get('interesting') or ():
            if entry.get('id'):
                add('vulnerability', url, {'id': entry['id'], 'severity': entry.get('severity'),
                                           'detail': entry.get('detail')}, entry['id'])
        for probe in output.get('probes') or ():
            if probe.get('status') and probe.get('path'):
                add('endpoint', probe.get('path'), {'status': probe.get('status'),
                                                    'length': probe.get('length')},
                    f"{url}{probe.get('path')}")
    elif tool_id == 'nexus.post.pivot_bruteforce' and result.verification_method == 'pivot_credential_validated':
        # The credential was validated from the authorized host, against a form
        # that provably rejects a wrong password (both re-checked twice by the
        # remote harness). That proves the *password*, not a session: the fact
        # carries the handle and the pivoted endpoint is never in scope, so it is
        # keyed on the SSH host the engagement really covers (V1-29/V1-31).
        host = output.get('target')
        tenant = str(getattr(context, 'tenant_id', 'system'))
        for credential in output.get('valid_credentials') or ():
            username = credential.get('username')
            add('credential', host, {'username': username,
                                     'secret_ref': _credential_handle(credential, tenant_id=tenant),
                                     'service': 'http-pivot'},
                f"pivot:{username}@{output.get('form_url')}")
    elif tool_id == 'nexus.cred.bruteforce' and result.verification_method in {
        'cred_bruteforce_completed', 'tcp_positive_marker'
    }:
        # hydra only prints a hit it actually authenticated, so every row is a
        # credential the service accepted. A completed sweep with no hit promotes
        # nothing (the negative is a valid result, not evidence). The plaintext
        # stays in the vault: the fact carries the handle (V1-29), and no
        # ``access`` is derived - a validated password is not a session (V1-31).
        target = output.get('target')
        service = output.get('service')
        tenant = str(getattr(context, 'tenant_id', 'system'))
        for credential in output.get('valid_credentials') or ():
            username = credential.get('username') or output.get('username')
            add('credential', target, {'username': username,
                                       'secret_ref': _credential_handle(credential, tenant_id=tenant),
                                       'service': service},
                f"cred:{service}:{username}@{target}")
    elif tool_id == 'nexus.web.wp_bruteforce' and result.verification_method == 'wp_credential_validated':
        username = output.get('username')
        tenant = str(getattr(context, 'tenant_id', 'system'))
        for credential in output.get('valid_credentials') or ():
            add('credential', username, {'username': credential.get('username'),
                                         'secret_ref': _credential_handle(credential, tenant_id=tenant),
                                         'service': 'wordpress'},
                f"wordpress:{username}")
    elif tool_id == 'nexus.web.wp_exec' and result.verification_method == 'wp_command_executed':
        target = output.get('url')
        add('access', target, {'transport': 'http', 'service': 'wordpress',
                               'theme': output.get('theme'), 'file': output.get('file')})
        for entry in output.get('outputs') or ():
            stdout = (entry.get('stdout') or '').strip()
            command = (entry.get('command') or '').strip()
            if command in ('id', 'id -u', 'whoami') and (
                re.search(r'uid=0\(root\)', stdout) or stdout in ('0', 'root')
            ):
                add('privilege', target, {'uid': 0, 'user': 'root'})
            for flag in FLAG_RE.findall(stdout):
                add('loot', flag, {'flag': flag, 'command': command, 'service': 'wordpress'}, flag)
    elif tool_id == 'nexus.win.winrm_exec' and result.verification_method == 'winrm_command_executed':
        # The channel itself is proven: the harness only reports
        # ``winrm_command_executed`` after NetExec authenticated *and* printed its
        # "Executed command" marker, so the credential used is an access fact.
        target = output.get('target')
        domain = arguments.get('domain') or ''
        username = arguments.get('username')
        add('access', target, {'transport': 'winrm', 'username': username,
                               'domain': domain or None})
        command = (output.get('command') or '').strip()
        stdout = (output.get('stdout') or '').strip()
        # Privilege is only claimed from an identity query that names an
        # administrative group; a listing of *other* accounts never promotes the
        # operator's own session.
        if _WIN_IDENTITY_RE.match(command) and _WIN_ADMIN_RE.search(stdout):
            add('privilege', target, {'username': username, 'domain': domain or None,
                                      'source': 'winrm:whoami'})
        # ``net (local)group <admin group> /domain`` names the accounts inside a
        # domain-administrative group; each member is privileged *in the domain*,
        # so the fact is keyed on the account, not on the host that enumerated it.
        query = _WIN_GROUP_QUERY_RE.match(command)
        if query:
            group = query.group('group').strip('"\'')
            if group.lower() in _WIN_ADMIN_GROUPS:
                for account in _net_group_members(stdout):
                    if account.lower() in _WIN_ADMIN_GROUPS:
                        continue
                    key = f"domain-admin:{account}@{domain}" if domain else f"domain-admin:{account}"
                    add('privilege', target, {'account': account, 'domain': domain or None,
                                              'group': group, 'source': 'winrm:net-group'},
                        key)
        # Loot is only attributed when the command read exactly one literal file.
        read = _WIN_READ_RE.match(command)
        if read:
            path = read.group('path').strip('"\'')
            for flag in FLAG_RE.findall(stdout):
                add('loot', flag, {'flag': flag, 'path': path, 'command': command,
                                   'service': 'winrm'}, path)
    elif tool_id == 'nexus.post.dpapi' and result.verification_method == 'dpapi_unwrapped':
        # The blob's own signature was verified before the material was released, so
        # the recovered key material is a proven fact (never the AP itself: only its
        # hash and the masterkey it belongs to).
        add('credential', output.get('master_key_guid') or 'dpapi-material',
            {'service': 'dpapi', 'master_key_guid': output.get('master_key_guid'),
             'material_sha256': output.get('material_sha256'),
             'crypt_algo': output.get('crypt_algo')},
            f"dpapi:{output.get('master_key_guid') or 'material'}")
    elif tool_id == 'nexus.post.dpapi' and result.verification_method == 'kdbx_opened':
        # ``kdbx_opened`` is only reported after the DPAPI-recovered material derived
        # the database key and every payload block hash was checked, so an entry's
        # secret is a verified credential and a flag-shaped one is loot. The secret
        # itself reaches the blackboard as a handle (V1-29): the entry is stored in
        # the vault and the fact carries ``secret_ref``, never the plaintext.
        tenant = str(getattr(context, 'tenant_id', 'system'))
        for entry in output.get('entries') or ():
            title = entry.get('title') or entry.get('group') or 'entry'
            password = entry.get('password') or ''
            if entry.get('username') or password:
                add('credential', title,
                    {'username': entry.get('username') or None,
                     'secret_ref': _credential_handle(entry, tenant_id=tenant) or None,
                     'group': entry.get('group'),
                     'service': 'keepass'},
                    f"keepass:{entry.get('group')}/{title}")
            for flag in FLAG_RE.findall(password):
                add('loot', flag,
                    {'flag': flag, 'title': title, 'group': entry.get('group'),
                     'service': 'keepass'}, title)
    elif tool_id == 'nexus.recon.dns' and result.verification_method == 'dns_response_parsed':
        # A DNS answer is a server-provided record set, not an operator guess. Only
        # a flag-shaped token inside an observed record value is promoted to loot
        # (measured: the room's flag lived in a TXT record of the domain).
        server = output.get('server')
        for flag in output.get('flags') or ():
            add('loot', flag, {'flag': flag, 'record_type': output.get('record_type'),
                               'name': output.get('name'), 'server': server}, flag)
    elif (tool_id == 'nexus.exploit.msf_exploit'
          and result.verification_method == _MSF_SESSION_RESULT_METHOD):
        # A session the provenance verifier accepted (V1-24): the exploit really
        # ran against the engaged target and the session that appeared while the
        # job ran reports that same host. Measured in rerun 6
        # (run_66eb363ed2fd42bf9d30985b76bf3248): ms17_010_psexec opened a SYSTEM
        # Meterpreter, the handler verified it and `kernel_sessions` got its
        # first row -and the planner never saw any of it, because this function
        # asserted nothing for the tool and `exploitation` could not close.
        #
        # Only `session_established` promotes: `session_provenance_ambiguous`
        # (zero or several candidates in the window) and
        # `session_provenance_unverified` (a session reporting another host)
        # describe a session whose origin is not proven to be this job, so they
        # assert nothing about the engagement -the 9A verifier already decided
        # that, this module only stops contradicting it.
        record = output.get('session') if isinstance(output.get('session'), dict) else {}
        session_uuid = str(output.get('session_uuid') or record.get('uuid') or '')
        target = str(output.get('target') or record.get('session_host') or '')
        if session_uuid and target:
            via_exploit = str(record.get('via_exploit') or output.get('module') or '')
            owner = _session_owner(record)
            sid = _session_sid(result)
            add('session', target,
                {'session_uuid': session_uuid, 'via_exploit': via_exploit,
                 'target': target, 'user': owner or None, 'sid': sid},
                f'{target}:{session_uuid}', method=MSF_SESSION_METHOD)
            if owner:
                # Only a descriptor that names an account can substantiate the
                # access claim: the fact is keyed on that account, and without
                # one there is no identity to key it on.
                add('access', target,
                    {'kind': str(record.get('type') or ''), 'user': owner,
                     'via_exploit': via_exploit},
                    f'{target}:{owner}@{session_uuid}', method=MSF_SESSION_METHOD)
    elif tool_id == 'nexus.c2.sliver_loot' and result.verification_method == 'sliver_loot_recorded':
        loot = output.get('loot') or {}
        if loot.get('sha256'):
            add('loot', loot.get('loot_id') or loot.get('name'),
                {'sha256': loot['sha256'], 'size': loot.get('size')},loot.get('name'))
    return rows


def persist_assertions(assertions, context, tool_id):
    scope = context.scope
    if not scope or not context.store:
        return
    board = Blackboard(context.store)
    for item in assertions:
        board.record(tenant_id=context.tenant_id, engagement_id=scope.engagement_id,
                     fact_type=item['fact_type'], key=item['key'], value=item['value'],
                     source=tool_id, created_by='deterministic-verifier', verified=True,
                     asserted_by='verifier', verification_method=item['verification_method'],
                     invocation_id=item['invocation_id'])
