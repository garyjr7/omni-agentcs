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
from typing import Any, NamedTuple
from urllib.parse import parse_qs, parse_qsl, unquote_plus, urlsplit

from .blackboard import Blackboard, is_verified_fact
from .route_facts import route_key

#: Flag-shaped tokens (``flag{fake_flag}``, ``flag{fake_flag}``, ``flag{fake_flag}``) found in the
#: output of a verified command execution. Keeping the prefixes explicit avoids
#: turning any brace-wrapped text into "loot".
FLAG_RE = re.compile(r"(?:THM|HTB|FLAG|flag|CTF|ctf)\{[^}\s\x00]{4,200}\}")

#: A read of **one** file that ends the command (``cat``/``type``, optionally
#: behind ``sudo``, or the PowerShell ``Get-Content``/``gc``). The read may follow
#: other commands (``id; hostname; cat /home/x/user.txt`` is a shape a real run
#: produced), but nothing may run *after* it: a pipe, a loop or a later statement
#: mixes outputs, and then no line can be attributed to the file. Matching only
#: the *text* of the command is what lets the same rule serve ``ssh_exec``,
#: ``shell.exec`` and ``winrm_exec`` without pinning one exact command line.
_FLAG_FILE_READ_RE = re.compile(
    r"(?:^|[;&|\n])\s*"
    r"(?:sudo\s+(?:-[A-Za-z]+\s+)*)?"
    r"(?:cat|tac|less|more|type|get-content|gc)\s+"
    r"(?P<path>\"[^\"]+\"|'[^']+'|[^\s|;&<>]+)"
    r"(?:\s+2>>?\s*(?:/dev/null|&1))?"
    r"\s*$",
    re.IGNORECASE,
)

#: Conventional CTF flag files (``user.txt``, ``root.txt``, ``flag.txt``,
#: ``flag1.txt``...). The *name* is what makes a verified read loot; Simple CTF
#: stores ``G00d j0b, keep up!`` in ``user.txt``, with no ``flag{fake_flag}`` shape, and
#: the engine used to record nothing because of it. Both separators count: the
#: PowerShell branch reads ``C:\\Users\\tom\\Desktop\\user.txt``.
_FLAG_FILE_NAME_RE = re.compile(
    r"(?:^|[/\\])(?:user|root|flag|proof|local|system)(?:[._-]?\d+)?\.txt$",
    re.IGNORECASE,
)

#: Longest file content promoted as loot; a longer line is not a flag and
#: truncating it would store a text that never existed on the target. The format
#: is never guessed (Vulnversity's ``user.txt`` holds an MD5, ``8bd7992f...``),
#: so the only thing that bounds "this is the capture" is that it is short.
FLAG_FILE_TEXT_MAX = 200

#: ``verification_method`` of the facts a generic shell asserts when the command
#: it ran was an authenticated ``ssh`` (``sshpass``). The channel is proven -the
#: command really ran on the target- but by ``nexus.shell.exec`` rather than by
#: ``nexus.post.ssh_exec``, so the board can tell the two apart.
SHELLPASS_METHOD = "shell_sshpass_completed"

#: ``verification_method`` of the ``nexus.shell.exec`` result these facts come
#: from. ``shell_command_denied``/``shell_unavailable`` never get this far
#: (``ToolResult.success`` is false), so the check only pins the contract.
SHELL_RESULT_METHOD = "shell_exit_code"

#: Query/form parameter names a webshell (or any command panel) uses to carry
#: the command. Only these names let the verifier attribute an output to a
#: command channel; a page that merely contains ``uid=`` proves nothing.
WEB_COMMAND_PARAMS: tuple[str, ...] = ("c", "cmd", "command", "exec", "run", "shell")

#: ``verification_method`` of the facts a command-driven web shell asserts. The
#: channel is proven because the request carried a command and the response is
#: its output (the canonical ``uid=<n>(<user>) gid=<n>`` line); it is written by
#: ``nexus.web.request`` or by ``nexus.shell.exec`` running ``curl``.
WEB_SHELL_METHOD = "web_command_completed"

#: ``verification_method`` of a vulnerability the *database* confirmed. The
#: caller's payload ran only if the engine answered with its own error text.
SQLI_ERROR_METHOD = "http_sql_error"

#: ``verification_method`` of an ``access`` fact a *page* proved: the request
#: carried a session the engine had stored, and the response served the page
#: behind it. It is the mirror image of the SSH channel -the session admits the
#: client, no command runs yet- so the board can tell it from a shell.
HTTP_SESSION_METHOD = "http_session_authenticated"

#: A page served only to an authenticated visitor offers a way out: a logout /
#: sign-out affordance. It is a *positive* marker, and a login page never has
#: one, so it decides the verdict on its own.
_LOGOUT_AFFORDANCE_RE = re.compile(
    r"log\s*-?\s*out|sign\s*-?\s*out|cerrar\s+sesi[oó]n|desconectar", re.IGNORECASE
)

#: Paths that live behind a login in virtually every application. The second
#: positive marker, and only when the body does not deny: hijack_v5 measured a
#: 200 on ``/administration.php`` whose body said "Access denied", which is a
#: rejected session, not the panel.
_PROTECTED_PATH_RE = re.compile(
    r"^/(?:admin(?:istrator|istration)?|dashboard|panel|private|internal|account|"
    r"profile|settings|users?|backend|manage|console)(?:[/.]|$)",
    re.IGNORECASE,
)

#: Text that refuses the request. It only ever *blocks* an assertion, so the list
#: is deliberately wide (a false negative costs a turn, a false positive lies).
_ACCESS_DENIED_RE = re.compile(
    r"access\s+denied|acceso\s+denegado|not\s+authori[sz]ed|unauthori[sz]ed|"
    r"permission\s+denied|permisos\s+insuficientes|login\s+required|"
    r"please\s+(?:log|sign)\s*in|debes\s+iniciar\s+sesi[oó]n|"
    r"no\s+tienes?\s+(?:permisos|acceso)|forbidden",
    re.IGNORECASE,
)

#: A ``<input type="password">`` means the server answered with the login form:
#: that is what a rejected session looks like, and it is never access.
_LOGIN_FORM_RE = re.compile(r"type\s*=\s*[\"']?password", re.IGNORECASE)


def access_denied_page(body) -> bool:
    """Whether a response body refuses the request it answered."""
    text = str(body or "")
    return bool(text) and bool(_ACCESS_DENIED_RE.search(text))


def authenticated_page_signal(body, path: str) -> str:
    """Positive marker of a page only a session gets: why it counts, or ``""``.

    Returns ``"logout_affordance"`` or ``"protected_path"``. A login form or a
    denial page returns ``""`` whatever the path says: the verdict is read from
    the response, never inferred from the URL alone.
    """
    text = str(body or "")
    if not text or _LOGIN_FORM_RE.search(text) or access_denied_page(text):
        return ""
    if _LOGOUT_AFFORDANCE_RE.search(text):
        return "logout_affordance"
    if _PROTECTED_PATH_RE.search(str(path or "")):
        return "protected_path"
    return ""


def http_session_evidence(arguments, output) -> dict | None:
    """The ``access`` value a response that *used* a session proves, or ``None``.

    Measured in hijack_v5 (``run_bc2ff878a44641afa8f04dc90168f22f``, 2026-10-29):
    ``nexus.web.request`` sent the ``session_ref`` the credential tool had issued
    against ``/administration.php``, got a 200 and asserted nothing, so the plan
    stayed on *Acceso inicial* while the model re-tried the login for 27 turns.
    The request has to carry the session (``session_ref`` or a literal ``cookie``),
    answer 2xx and serve an authenticated page; a denial or a login form is not
    access, whatever the status code says.
    """
    args = arguments if isinstance(arguments, dict) else {}
    sent = str(args.get("session_ref") or "").strip() or str(args.get("cookie") or "").strip()
    if not sent:
        return None
    payload = output if isinstance(output, dict) else {}
    status = payload.get("status")
    if not isinstance(status, int) or not 200 <= status < 300:
        return None
    url = str(payload.get("url") or args.get("url") or "")
    try:
        path = urlsplit(url).path or "/"
    except ValueError:
        path = "/"
    signal = authenticated_page_signal(payload.get("body_preview"), path)
    if not signal:
        return None
    return {
        "transport": "http",
        "authenticated": True,
        "session_ref": str(args.get("session_ref") or "").strip() or None,
        "status": status,
        "path": path,
        "signal": signal,
    }


#: ``verification_method`` of an identity a page *printed*. The parser read an
#: address out of the body, so the fact is verified for what it says -this string
#: is published- and carries ``confidence: observed`` because an address on a
#: page is not proof that the directory holds the account. Derived usernames
#: (name + convention) never reach the board through this path: they travel in
#: the observation as candidates, ranked, until a directory answers.
WEB_IDENTITY_METHOD = "web_identity_extracted"

#: ``verification_method`` values of the unauthenticated user enumeration. Both
#: answer "this account exists in the directory"; only kerbrute also proves
#: absence, and absence is never written as a fact (there is no negative type,
#: and a branch closes with a ``barrier`` that states its reason).
USER_ENUM_METHODS = ("userenum_kerbrute_parsed", "userenum_asrep_parsed")

#: Error text only the database produces when an injected expression executed.
#: Each entry names the engine and the literal that identifies it -never the
#: leaked value- so the fact can say "this is injectable, MySQL" without copying
#: credentials into the board.
_SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql", re.compile(r"XPATH syntax error:\s*'~")),
    ("mysql", re.compile(r"You have an error in your SQL syntax", re.I)),
    ("microsoft sql server",
     re.compile(r"Unclosed quotation mark after the character string", re.I)),
    ("microsoft sql server", re.compile(r"Incorrect syntax near", re.I)),
    ("postgresql", re.compile(r"ERROR:\s+syntax error at or near", re.I)),
    ("oracle", re.compile(r"ORA-\d{4,5}:", re.I)),
    ("sqlite", re.compile(r"unrecognized token:.*SQLITE_ERROR", re.I | re.S)),
)

#: Tokens that make the *request* an injection attempt instead of an ordinary
#: page load. A stale error printed by a page nobody attacked proves nothing, so
#: both halves are required: the caller sent a payload and the engine answered.
_SQLI_PAYLOAD_TOKENS: tuple[str, ...] = (
    "extractvalue", "updatexml", "information_schema", "union select",
    "concat(", "or 1=1", "sleep(", "benchmark(", "waitfor delay", "0x7e",
    "%27", "'",
)

#: The identity line a command channel prints. Same canonical shape the SSH
#: branch accepts: the channel is proven by the command that really ran.
_WEB_IDENTITY_RE = re.compile(r"uid=(\d+)\(([^)\s]+)\)\s+gid=\d+")

#: A webshell usually wraps the command output in HTML (``<pre>…</pre>``). The
#: tags are markup, not the file: without stripping them the *last line* of a
#: ``cat /root/root.txt`` was ``</pre>`` and the bench accepted it as the flag
#: (measured in Vulnversity, 2026-10-19, second post-fix run).
_MARKUP_TAG_RE = re.compile(r"<[^>\n]{1,200}>")

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
    """Content printed by a read of a flag file over the shell channel.

    The summary is the *local* shell output, so the client's own diagnostics are
    removed first. The same rule as :func:`flag_file_text` applies: a plain read
    must leave exactly one line, and a read that closes a chain of commands
    (``id; hostname; cat user.txt``) takes the last one, because everything
    before it belongs to the earlier commands.
    """
    path, chained = flag_file_read(command)
    if not path:
        return ""
    stdout = str(summary or "").split("\n[stderr]", 1)[0]
    lines = [line.strip() for line in stdout.splitlines()
             if line.strip() and not _SSH_CLIENT_NOISE_RE.match(line.strip())]
    if not lines or (not chained and len(lines) != 1):
        return ""
    text = lines[-1]
    if len(text) > FLAG_FILE_TEXT_MAX or any(ord(ch) < 0x20 for ch in text):
        return ""
    if _FLAG_ERROR_RE.search(text):
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

#: NetExec's admin marker: ``CORP\\administrator:Passw0rd (Pwn3d!)``. The printed
#: credential is never copied into a fact -only the account name is- so the
#: password cannot reach the board by this path.
_PWN3D_RE = re.compile(r"(?P<credential>[^\s()]+)\s+\(Pwn3d!\)", re.IGNORECASE)

#: ``NT AUTHORITY\SYSTEM`` printed by the remote command of psexec/winrm.
_SYSTEM_ACCOUNT_RE = re.compile(r"nt\s+authority\\system", re.IGNORECASE)

#: ``Get-Content <path>`` / ``type <path>`` / ``cat <path>`` reading exactly one
#: literal file: no pipes, no wildcards, no loops, no redirections. Only this
#: shape lets the verifier attribute a flag to the path that was read.
_WIN_READ_RE = re.compile(
    r"^\s*(?:get-content|gc|type|cat)\s+(?P<path>\"[^\"]+\"|'[^']+'|[^\s|;<>]+)\s*$",
    re.IGNORECASE,
)


def flag_file_read(command):
    """``(path, chained)`` of the flag-file read that ends *command*.

    ``path`` is empty when the command does not end in a read of a conventional
    flag file. ``chained`` says other commands ran before the read (``id;
    hostname; cat user.txt``), so only the *last* line of the output belongs to
    the file; a command that is exactly one read must print exactly one line,
    because anything else is not the content of a one-line flag file.
    """
    text = str(command or "")
    match = _FLAG_FILE_READ_RE.search(text)
    if not match:
        return "", False
    path = match.group("path").strip("\"'")
    if not _FLAG_FILE_NAME_RE.search(path):
        return "", False
    return path, bool(text[: match.start()].strip())


def flag_file_path(command):
    """Path a command reads, when that command ends in a read of a flag file."""
    return flag_file_read(command)[0]


#: A command channel has no exit code of its own (a webshell answers 200 even
#: when the remote command failed), so the *text* has to say it. Measured after
#: the first web-channel fix (Vulnversity, 2026-10-19): ``cat /root/root.txt``
#: as ``www-data`` returned ``cat: /root/root.txt: Permission denied`` and the
#: bench counted that line as the second flag. An error is not a capture.
_FLAG_ERROR_RE = re.compile(
    r"permission denied|operation not permitted|no such file|not found|"
    r"cannot open|cannot read|is a directory|command not found|"
    r"^\s*(?:cat|grep|ls|find|sh|bash|/bin/sh|/bin/bash|python[0-9.]*|perl|curl|wget):\s",
    re.IGNORECASE,
)


def flag_file_text(command, stdout):
    """Content of the flag file a verified read printed, or ``""``.

    The format is not interpreted: whatever short text the file holds *is* the
    flag (Vulnversity's ``user.txt`` is an MD5). ``chained`` reads take the last
    line -the only one the trailing read produced- and a plain read must leave
    exactly one, so a multi-line answer (a hint, an error, someone else's
    output) is never stored as the file's content.
    """
    path, chained = flag_file_read(command)
    if not path:
        return ""
    lines = [
        line.strip()
        for line in str(stdout or "").splitlines()
        if line.strip() and not _SSH_CLIENT_NOISE_RE.match(line.strip())
    ]
    if not lines or (not chained and len(lines) != 1):
        return ""
    text = lines[-1]
    if len(text) > FLAG_FILE_TEXT_MAX or any(ord(ch) < 0x20 for ch in text):
        return ""
    if _FLAG_ERROR_RE.search(text):
        return ""
    return text


def web_command_from_url(url) -> str:
    """Remote command carried by *url* (``?c=id``, ``?cmd=cat+user.txt``), or "".

    ``parse_qs`` decodes the value, so ``+`` and ``%20`` become spaces before
    :func:`flag_file_read` sees it. An empty value is not a command.
    """
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return ""
    for name, values in parse_qs(parts.query, keep_blank_values=False).items():
        if name.casefold() in WEB_COMMAND_PARAMS and values:
            return str(values[0])
    return ""


def web_command_from_curl(command) -> tuple[str, str]:
    """``(url, remote command)`` of a ``curl``/``wget`` call, or ``("", "")``.

    A webshell is driven with either ``curl 'http://host/shell.phtml?c=id'`` or
    ``curl -G http://host/shell.phtml --data-urlencode 'c=cat user.txt'``. Both
    shapes are read here so the generic shell can be verified as the HTTP
    channel it really is, without trusting a note the model wrote.
    """
    text = str(command or "")
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:  # unbalanced quote: the shell would have refused it too
        return "", ""
    if not any(_program_name(token) in {"curl", "wget"} for token in tokens):
        return "", ""
    url = next(
        (token for token in tokens if token.startswith(("http://", "https://"))), ""
    )
    if not url:
        return "", ""
    remote = web_command_from_url(url)
    if remote:
        return url, remote
    for index, token in enumerate(tokens):
        if token in {"--data-urlencode", "-d", "--data", "--data-raw"} and index + 1 < len(tokens):
            name, _, value = tokens[index + 1].partition("=")
            if name.casefold() in WEB_COMMAND_PARAMS:
                return url, unquote_plus(value)
    return url, ""


def http_channel_assertions(add, *, target: str, command: str, body: str, method: str) -> None:
    """Promote a proven web command channel to ``access``/``privilege``/``loot``.

    The caller has already established that the request carried a command
    (:func:`web_command_from_url` / :func:`web_command_from_curl`); this function
    only reads what the response proves. A canonical identity line is the
    channel. A command that ends in ``cat`` of a conventional flag file (or a
    flag-shaped token in its output) is the capture, with the same narrow rules
    the SSH branch uses: the format is never guessed and a multi-line answer is
    never attributed to one file.
    """
    text = _MARKUP_TAG_RE.sub("", str(body or ""))
    identity = _WEB_IDENTITY_RE.search(text)
    if identity:
        uid, user = int(identity.group(1)), identity.group(2)
        add("access", target,
            {"transport": "http", "uid": uid, "user": user,
             "command": command, "via": "web"},
            method=method)
        if uid == 0:
            add("privilege", target, {"uid": 0, "user": "root", "via": "web"},
                method=method)
    remote = str(command or "").strip()
    if not remote:
        return
    captured = FLAG_RE.findall(text)
    for flag in captured:
        # The flag is the *key* (its identity on the board); the target stays the
        # host that produced it. Measured in Bounty Hacker v2 (2026-10-31): the
        # loot fact carried the flag as ``target``, so the closure and the report
        # attributed the capture to a string that is not a host.
        add("loot", target,
            {"flag": flag, "command": remote, "service": "http", "via": "web"},
            flag, method=method)
    path = flag_file_path(remote)
    content = flag_file_text(remote, text) if path else ""
    if content and content not in captured:
        add("loot", target,
            {"content": content, "flag": content, "command": remote,
             "path": path, "service": "http", "via": "web"},
            f"http:file:{path}", method=method)


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


def netexec_admin_accounts(entries) -> tuple[tuple[str, str], ...]:
    """``(domain, username)`` of every row NetExec marked ``Pwn3d!``.

    NetExec prints the marker only after it authenticated *and* its own admin
    check succeeded, so the row is a proven local-administrator session -not a
    guess. The credential NetExec echoes (``CORP\\administrator:Passw0rd``) is
    parsed for the account name and thrown away: the password never becomes a
    fact (V1-29).
    """
    accounts: list[tuple[str, str]] = []
    for entry in entries or ():
        text = str((entry or {}).get("text") or "")
        match = _PWN3D_RE.search(text)
        if match is None:
            continue
        credential = match.group("credential")
        account = credential.split(":", 1)[0].strip()
        domain, _, username = account.partition("\\")
        if not username:
            username, domain = domain, ""
        username = username.strip()
        if not _WIN_ACCOUNT_RE.match(username):
            continue
        pair = (domain.strip(), username)
        if pair not in accounts:
            accounts.append(pair)
    return tuple(accounts)


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


def _sqli_parameter(url: str) -> str:
    """Name of the query parameter that carries an injection payload, if any.

    Only a request that *attacks* something can be turned into a finding: the
    body has to name the engine error and the query string has to show the
    payload. An unrelated page that happens to display a stale SQL error is left
    alone, which is what keeps this from becoming a false-positive generator.
    """
    query = urlsplit(url).query
    if not query:
        return ""
    if not any(token in query.lower() for token in _SQLI_PAYLOAD_TOKENS):
        return ""
    for name, value in parse_qsl(query, keep_blank_values=True):
        if any(token in value.lower() for token in _SQLI_PAYLOAD_TOKENS):
            return name
    return ""


def sql_error_signature(text: str) -> tuple[str, str] | None:
    """``(dbms, indicator)`` when ``text`` carries an engine error only SQL prints."""
    for dbms, pattern in _SQL_ERROR_SIGNATURES:
        match = pattern.search(text)
        if match:
            return dbms, match.group(0)
    return None


def _fact_anchor(context: Any, fact_type: str, key: Any, relation: str) -> tuple[str, str] | None:
    """``(uri, relation)`` of a fact this assertion came from (``None`` if unknown).

    The URI is the same one :class:`Blackboard` writes, so the edge lands where
    the graph reads it. A verifier that cannot name its origin (no engagement, no
    key) simply contributes no edge: the fact is still recorded and no orphan is
    invented.
    """
    if not key:
        return None
    engagement = str(
        getattr(context, "engagement_id", "")
        or getattr(getattr(context, "scope", None), "engagement_id", "")
        or ""
    )
    if not engagement:
        return None
    from .blackboard import fact_uri

    return fact_uri(engagement, fact_type, str(key)), relation


def derive_assertions(tool_id, arguments, result, context):
    # A determinate "no" is never evidence *for* anything. Some handlers mark a
    # negative observation as ``verified`` (they proved the directory is empty),
    # which makes ``success`` true while the outcome is still ``negative``; the
    # contract is explicit, so no parser branch may promote it into a fact.
    if str(getattr(result, "outcome", "") or "") in {
        "negative",
        "denied",
        "unsupported",
        "in_flight",
    }:
        return []
    if not result.success or not context.invocation_id:
        return []
    output = result.output
    rows = []

    def add(kind, target, value, key=None, method=None, anchors=None):
        if not target:
            return
        rows.append(dict(fact_type=kind, target=str(target), key=str(key or target),
                         value=value, verified=True, asserted_by='verifier',
                         verification_method=method or result.verification_method,
                         invocation_id=context.invocation_id, run_id=context.run_id,
                         # JSON lists, not tuples: assertions travel through the
                         # ToolResult DTO, which only admits JSON containers.
                         anchors=[[str(item[0]), str(item[1])]
                                  for item in (anchors or ()) if item]))

    if tool_id == 'nexus.recon.nmap' and result.verification_method == 'nmap_xml_parsed':
        for host in output.get('scan', {}).get('hosts', []):
            if host.get('state') != 'up':
                continue
            target = host.get('ip')
            add('host', target, {'state': 'up'})
            host_anchor = _fact_anchor(context, 'host', target, 'host_has_service')
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    key = f"{target}:{port.get('port')}:{port.get('protocol')}"
                    add('service', target, port, key,
                        anchors=[host_anchor] if host_anchor else None)
    elif tool_id == 'nexus.recon.httpx' and result.verification_method == 'httpx_jsonl_parsed':
        for probe in output.get('probes', []):
            if probe.get('status_code'):
                url = str(probe.get('url') or '')
                parsed = urlsplit(url)
                host_name = parsed.hostname or str(probe.get('host') or '').split(':')[0]
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                anchors = [
                    anchor for anchor in (
                        _fact_anchor(context, 'service', f'{host_name}:{port}:tcp',
                                     'service_exposes_web'),
                        _fact_anchor(context, 'host', host_name, 'host_exposes_web'),
                    ) if anchor
                ]
                add('endpoint', url, probe, anchors=anchors)
    elif tool_id == 'nexus.recon.gobuster' and result.verification_method == 'gobuster_text_parsed':
        # The parser names the HTTP code ``status`` (its ``to_dict``), not
        # ``status_code``; reading the wrong key silently dropped every verified
        # hit, so a directory scan could never close ``enumeration`` and the plan
        # kept sending the run back to enumerate (measured in the Simple CTF run
        # of 2026-10-17: 11 hits, 0 assertions, 27 turns on the same phase).
        for hit in output.get('hits', []):
            if hit.get('status') or hit.get('status_code'):
                url = str(hit.get('url') or output.get('target') or '')
                parsed = urlsplit(url)
                host_name = parsed.hostname or url.split(':')[0]
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                anchors = [
                    anchor for anchor in (
                        _fact_anchor(context, 'service', f'{host_name}:{port}:tcp',
                                     'service_exposes_endpoint'),
                        _fact_anchor(context, 'host', host_name, 'host_exposes_endpoint'),
                    ) if anchor
                ]
                add('endpoint', url, hit, hit.get('path'), anchors=anchors)
    elif tool_id == 'nexus.post.ssh_exec' and result.verification_method in SSH_EXEC_CHANNEL_METHODS:
        target = output.get('target')
        username = arguments.get('username')
        port = arguments.get('port')
        port = port if isinstance(port, int) and 0 < port < 65536 else None
        # Graph anchors: the host and the SSH service are the origin of the
        # access/credential, and the credential is the origin of the privilege.
        host_anchor = _fact_anchor(context, 'host', target, 'host_yields_access')
        service_anchor = _fact_anchor(
            context, 'service', f'{target}:{port or 22}:tcp', 'service_yields_credential'
        )
        credential_key = f'cred:ssh:{username}@{target}' if username else ''
        credential_anchor = (
            _fact_anchor(context, 'credential', credential_key,
                         'credential_grants_privilege')
            if credential_key else None
        )
        access_anchor = _fact_anchor(context, 'access', target, 'access_grants_privilege')
        origin = [item for item in (service_anchor, host_anchor) if item]
        # The port rides with the access fact: it is the one an authenticated
        # session really used, so the handlers can complete a later call from the
        # board instead of falling back to 22 (Simple CTF runs on 2222).
        add('access', target, {'transport': 'ssh', 'username': username, 'port': port},
            anchors=origin)
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
                f'cred:ssh:{username}@{target}', anchors=origin)
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
            add('privilege', target, {'uid': 0, 'user': 'root'},
                anchors=[item for item in (credential_anchor, access_anchor) if item])
        # A flag-shaped token in the output of a verified authenticated command is
        # loot: the channel is proven, so the flag came from a command that really
        # ran on the host. Same contract as ``nexus.web.wp_exec`` (the Windows
        # channel stays stricter and only attributes a single literal file read).
        if output.get('exit_status') == 0:
            captured = FLAG_RE.findall(stdout)
            for flag in captured:
                add('loot', target,
                    {'flag': flag, 'command': command, 'service': 'ssh'}, flag,
                    anchors=[item for item in (access_anchor, host_anchor) if item])
            # A verified read of a conventional flag file is loot on its own
            # evidence: the SSH channel is proven (exit 0) and the path says what
            # the text is, so a room whose flags carry no prefix still registers
            # the capture. The *content* is never interpreted: Vulnversity's
            # ``user.txt`` holds an MD5 (``8bd7992f...``), and any short text the
            # file printed counts. The read may close a chain of commands
            # (``id; hostname; cat user.txt``), which is the shape a measured run
            # produced; only the trailing read's own line is attributed.
            path = flag_file_path(command)
            text = flag_file_text(command, stdout)
            if text and text not in captured:
                add('loot', target,
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
        if not channels and exit_code == 0:
            # The webshell driven with curl is the same kind of channel: the
            # command rides in the URL/body and the response is its output.
            url, remote = web_command_from_curl((arguments or {}).get('command'))
            host = urlsplit(url).hostname or ''
            if host and remote:
                http_channel_assertions(
                    add, target=host, command=remote,
                    body=_shell_output(output, result), method=WEB_SHELL_METHOD,
                )
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
                    add('loot', first.target,
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
                    add('loot', first.target,
                        {'content': content, 'flag': content,
                         'command': first.command, 'path': path,
                         'service': 'ssh', 'via': 'shell.exec'},
                        f'ssh:file:{path}', method=SHELLPASS_METHOD)
    elif tool_id == 'nexus.web.request' and result.verification_method == 'http_response_received':
        # A webshell is a real command channel, and until this branch existed
        # the verifier was blind to it: Vulnversity's run (2026-10-19) got
        # ``uid=33(www-data)`` through an uploaded ``.phtml`` and recorded
        # ``access`` as a *hypothesis*, so ``exploitation`` could never close
        # and the plan kept pushing the model back to initial access while the
        # command channel was already open. Only a request that carries the
        # command is attributed; a page that happens to print ``uid=`` is not.
        url = str((arguments or {}).get('url') or output.get('url') or '')
        remote = web_command_from_url(url)
        host = urlsplit(url).hostname or ''
        body = str(output.get('body_preview') or '')
        # What the page publishes about identity. Measured (HackPark): the run
        # downloaded a footer with ``j.doe@services.local`` and a team page with
        # the staff list, and the engine recorded neither, so it kept asking for
        # users with the users already on screen. Only the address is asserted;
        # the convention-derived usernames stay a ranked hypothesis in the
        # observation (``extracted.identities``) until a directory confirms them.
        extracted = output.get('extracted')
        if isinstance(extracted, dict):
            for address in extracted.get('emails') or ():
                text_address = str(address).strip()
                local, _, email_domain = text_address.partition('@')
                if not local or not email_domain:
                    continue
                # The key is the address / the local part on purpose: the
                # planner reads ``key`` to build the identity list, so a
                # prefixed key would put "web:user:j.doe" on the board instead
                # of a username a tool can use.
                add('email', text_address,
                    {'email': text_address, 'domain': email_domain,
                     'source': 'page', 'confidence': 'observed'},
                    method=WEB_IDENTITY_METHOD)
                add('user', local,
                    {'username': local, 'domain': email_domain,
                     'source': 'web_email', 'confidence': 'observed'},
                    method=WEB_IDENTITY_METHOD)
        # A session that opens the page behind the login is access in its own
        # right: no command runs yet, but the engagement *is* inside. The fact is
        # what closes ``exploitation`` in ``PHASES``; without it the plan stays on
        # *Acceso inicial* and the model re-tries the credential it already used.
        session = http_session_evidence(arguments, output)
        if host and session:
            add('access', host, session, method=HTTP_SESSION_METHOD)
        if host and remote:
            http_channel_assertions(
                add, target=host, command=remote,
                body=body,
                method=WEB_SHELL_METHOD,
            )
        # An error-based injection is an observation the model cannot invent: the
        # *database* answered the payload. Without this branch the verifier was
        # blind to it and the board learned nothing while a joomla run extracted
        # the admin hash 15 times in 50 turns (run_c71035d9818047eaa80dfd859e887b7c,
        # 2026-10-20: ``blackboard_delta = 0`` on every turn, 0 findings).
        parameter = _sqli_parameter(url)
        signature = sql_error_signature(body) if parameter else None
        if host and signature:
            dbms, indicator = signature
            # The endpoint without its query string: enough for the coverage
            # ledger to attribute the vector to the right port (``_mentions``
            # needs the host *and* a scheme/port/service, and the bare host in
            # the key is not one), and no payload is copied into the board.
            parts = urlsplit(url)
            endpoint = f"{parts.scheme or 'http'}://{parts.netloc}{parts.path or '/'}"
            add('vulnerability', host,
                {'class': 'error-based SQL injection', 'dbms': dbms,
                 'parameter': parameter, 'indicator': indicator,
                 'url': endpoint,
                 'method': str((arguments or {}).get('method') or 'GET')},
                f"sqli:{parts.path or '/'}:{parameter}",
                method=SQLI_ERROR_METHOD)
    elif tool_id == 'nexus.pwn.ret2libc' and result.verification_method == 'ret2libc_root_command':
        target = output.get('target')
        add('privilege', target, {'uid': 0, 'user': 'root'})
        flag = output.get('flag')
        if flag:
            add('loot', target, {'flag': flag, 'libc_base': output.get('libc_base')}, flag)
    elif tool_id == 'nexus.web.ssti' and result.verification_method == 'ssti_command_output':
        # Theseus (2026-10-30): the page rendered ``?key={{...}}`` and the engine
        # ran the command. The fact carries what is proven -parameter, engine and
        # the account the process runs as-, never the payload itself, so the
        # ledger can attribute the vector to the right port and the run stops
        # re-testing a page it already owns.
        url = output.get('url')
        parameter = output.get('parameter')
        parts = urlsplit(str(url or ''))
        endpoint = f"{parts.scheme or 'http'}://{parts.netloc}{parts.path or '/'}"
        add('vulnerability', url,
            {'class': 'server-side template injection',
             'engine': output.get('engine'), 'parameter': parameter,
             'rce': True, 'url': endpoint},
            f"ssti:{parts.path or '/'}:{parameter}")
        identity = _WEB_IDENTITY_RE.search(str(output.get('output') or ''))
        if identity:
            add('access', parts.hostname or url,
                {'transport': 'http', 'service': 'web', 'uid': int(identity.group(1)),
                 'username': identity.group(2), 'parameter': parameter})
        flag = output.get('flag')
        if flag:
            add('loot', parts.hostname or url, {'flag': flag, 'parameter': parameter}, flag)
    elif tool_id == 'nexus.post.pwnkit' and result.verification_method == 'pwnkit_root_command':
        # The nonce block reported ``uid=0(root)``: local root on a host reached
        # only through SSH. Same shape as the ret2libc proof.
        target = output.get('target')
        add('privilege', target, {'uid': 0, 'user': 'root'})
        flag = output.get('flag')
        if flag:
            add('loot', target, {'flag': flag}, flag)
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
        port = output.get('port')
        tenant = str(getattr(context, 'tenant_id', 'system'))
        anchors = [
            anchor for anchor in (
                _fact_anchor(context, 'service', f'{target}:{port}:tcp' if port else '',
                             'service_yields_credential'),
                _fact_anchor(context, 'host', target, 'host_yields_credential'),
            ) if anchor
        ]
        for credential in output.get('valid_credentials') or ():
            username = credential.get('username') or output.get('username')
            add('credential', target, {'username': username,
                                       'secret_ref': _credential_handle(credential, tenant_id=tenant),
                                       'service': service},
                f"cred:{service}:{username}@{target}", anchors=anchors)
    elif tool_id == 'nexus.post.crack_hash' and result.verification_method == 'crack_hash_john_show':
        # ``john --show`` reads its own pot file: a row there is a password john
        # recovered and verified against the hash, not a line the model typed.
        # The plaintext stays in the vault (V1-29); the fact carries the handle
        # so the next ``ssh_exec``/``web.request`` can consume it. The key is the
        # hash's host when the caller named one -that is what makes the handle
        # matchable by ``_board_ssh_credential``- and the username otherwise.
        tenant = str(getattr(context, 'tenant_id', 'system'))
        host = output.get('target') or ''
        hash_type = output.get('hash_type') or 'hash'
        for credential in output.get('valid_credentials') or ():
            username = credential.get('username')
            add('credential', host or username,
                {'username': username,
                 'secret_ref': _credential_handle(credential, tenant_id=tenant),
                 'service': hash_type,
                 'source': 'offline-crack',
                 **({'target': host} if host else {})},
                # The 4th argument is the fact's key: the host is what makes the
                # handle matchable by ``_board_ssh_credential``.
                host or f"hash:{hash_type}:{username}")
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
                add('loot', target,
                    {'flag': flag, 'command': command, 'service': 'wordpress'}, flag)
    elif (tool_id == 'nexus.recon.netexec'
          and result.verification_method == 'netexec_text_parsed'):
        # F1 (DeadDrop, 2026-10-23): the run reached the DC through a
        # ``proxychains4`` command typed into ``nexus.shell.exec``, and this
        # function asserted **nothing** for the only channel that worked, so a
        # dumped domain administrator closed as ``grounded: 0``. The ``Pwn3d!``
        # row is NetExec's own admin check: the account authenticated *and* is a
        # local administrator on that host, which is ``access`` plus
        # ``privilege`` -never a guess about a password.
        target = output.get('target')
        protocol = str(output.get('protocol') or 'smb')
        tenant = str(getattr(context, 'tenant_id', 'system'))
        password = (arguments or {}).get('password')
        for domain, account in netexec_admin_accounts(output.get('entries') or ()):
            add('access', target,
                {'transport': protocol, 'username': account,
                 'domain': domain or None, 'via': 'netexec'},
                f'{protocol}:{account}@{target}')
            add('privilege', target,
                {'account': account, 'domain': domain or None, 'host': target,
                 'source': 'netexec:pwn3d'},
                f'admin:{account}@{target}')
            if password:
                handle = _credential_handle(
                    {'password': password}, kind=protocol, tenant_id=tenant
                )
                if handle:
                    add('credential', target,
                        {'username': account, 'secret_ref': handle,
                         'service': protocol},
                        f'cred:{protocol}:{account}@{target}')
    elif (tool_id == 'nexus.attack.impacket_secretsdump'
          and result.verification_method == 'secretsdump_files_parsed'):
        # The dump files exist only after secretsdump authenticated *and* was
        # allowed to read SAM/NTDS, so the caller's channel is proven on its
        # own and every account in the files is a credential the engine
        # recovered. The NT hash is stored in the vault under its own kind so it
        # can never be handed out as a password (V1-29).
        target = output.get('target')
        domain = str((arguments or {}).get('domain') or '')
        caller = (arguments or {}).get('username')
        tenant = str(getattr(context, 'tenant_id', 'system'))
        if caller:
            add('access', target,
                {'transport': 'smb', 'username': caller, 'domain': domain or None,
                 'via': 'secretsdump'},
                f'smb:{caller}@{target}')
        for entry in output.get('entries') or ():
            entry = entry if isinstance(entry, dict) else {}
            username = str(entry.get('username') or '').strip()
            ntlm_hash = str(entry.get('ntlm_hash') or '').strip()
            if not username or not ntlm_hash:
                continue
            handle = _secret_handle(ntlm_hash, kind='ntlm', tenant_id=tenant)
            add('credential', target,
                {'username': username, 'domain': domain or None,
                 'secret_ref': handle or None, 'hash_type': 'ntlm',
                 'rid': entry.get('rid') or None,
                 'source': str(entry.get('source') or '') or None,
                 'service': 'smb', 'via': 'secretsdump'},
                f'ntlm:{username}@{target}')
            # RID 500 is the built-in administrator account of the database that
            # was dumped: its hash *is* the compromise of that authority. The
            # fact says exactly that and never invents a group membership the
            # tool did not print.
            if str(entry.get('rid') or '') == '500':
                add('privilege', target,
                    {'account': username, 'domain': domain or None,
                     'host': target, 'source': 'secretsdump:rid500'},
                    f'admin:{username}@{target}')
    elif (tool_id == 'nexus.attack.ad_user_enum'
          and result.verification_method in USER_ENUM_METHODS):
        # A Kerberos answer is the directory saying the account exists: no
        # password was sent, so no lockout counter moved (``lockout_risk`` is
        # published in the evidence). The AS-REP hash goes to the vault and the
        # fact keeps only the handle -the same rule as every other secret.
        domain = str((arguments or {}).get('domain') or output.get('domain') or '')
        for username in output.get('existing') or ():
            name = str(username).strip()
            if not name:
                continue
            add('user', name,
                {'username': name, 'domain': domain or None, 'exists': True,
                 'source': 'kerberos', 'lockout_risk': 'none'},
                method=result.verification_method)
        tenant = str(getattr(context, 'tenant_id', 'system'))
        for item in output.get('roastable') or ():
            entry = item if isinstance(item, dict) else {}
            name = str(entry.get('username') or '').strip()
            asrep_hash = str(entry.get('hash') or '').strip()
            if not name or not asrep_hash:
                continue
            handle = _secret_handle(asrep_hash, kind='krb5asrep', tenant_id=tenant)
            add('credential', f'{name}@{domain}' if domain else name,
                {'username': name, 'domain': domain or None,
                 'secret_ref': handle or None, 'hash_type': 'krb5asrep',
                 'source': 'kerberos_asrep', 'service': 'kerberos'},
                f'krb5asrep:{name}', method=result.verification_method)
    elif (tool_id == 'nexus.attack.impacket_psexec'
          and result.verification_method == 'psexec_output_parsed'):
        # psexec uploads a service binary and runs it as SYSTEM, so a successful
        # call is a command channel on that host. The privilege claim still waits
        # for the account name in the output: the remote command proves it, the
        # handler's design does not have to.
        target = output.get('target')
        domain = str((arguments or {}).get('domain') or '')
        username = str((arguments or {}).get('username') or '')
        auth = f'{domain}/{username}' if domain else username
        add('access', target,
            {'transport': 'smb-exec', 'username': username or None,
             'domain': domain or None, 'via': 'psexec'},
            f'smb-exec:{auth}@{target}')
        text = "\n".join(str(line) for line in (output.get('lines') or ()))
        if _SYSTEM_ACCOUNT_RE.search(text):
            add('privilege', target,
                {'account': 'SYSTEM', 'domain': domain or None,
                 'host': target, 'source': 'psexec:remote-identity'},
                f'admin:SYSTEM@{target}')
        command = str((arguments or {}).get('command') or '')
        read = _WIN_READ_RE.match(command)
        path = read.group('path').strip('"\'') if read else ''
        for flag in FLAG_RE.findall(text):
            add('loot', target,
                {'flag': flag, 'command': command, 'path': path or None,
                 'service': 'smb-exec', 'via': 'psexec'},
                path or flag)
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
                add('loot', target, {'flag': flag, 'path': path, 'command': command,
                                     'service': 'winrm'}, path)
            # The file name is the proof, not the format: ``Get-Content
            # user.txt``/``type user.txt`` printing one short line of any text is
            # the capture (Vulnversity's ``user.txt`` is an MD5). The channel is
            # already proven above, and ``flag_file_text`` refuses a multi-line
            # answer, so a wrapped/loud read promotes nothing.
            content = flag_file_text(command, stdout)
            if content and not any(row['value'].get('flag') == content for row in rows):
                add('loot', target,
                    {'content': content, 'flag': content, 'path': path,
                     'command': command, 'service': 'winrm'}, path)
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
                # The entry is the resource that held the flag; the flag is only
                # the key/value of the loot.
                add('loot', title,
                    {'flag': flag, 'title': title, 'group': entry.get('group'),
                     'service': 'keepass'}, title)
    elif tool_id == 'nexus.recon.dns' and result.verification_method == 'dns_response_parsed':
        # A DNS answer is a server-provided record set, not an operator guess. Only
        # a flag-shaped token inside an observed record value is promoted to loot
        # (measured: the room's flag lived in a TXT record of the domain).
        server = output.get('server')
        for flag in output.get('flags') or ():
            # The DNS server/record is the resource; the flag is the capture.
            add('loot', str(server or output.get('name') or 'dns'),
                {'flag': flag, 'record_type': output.get('record_type'),
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
            session_port = record.get('session_port') or output.get('port')
            anchors = [
                anchor for anchor in (
                    _fact_anchor(context, 'service',
                                 f'{target}:{session_port}:tcp' if session_port else '',
                                 'service_yields_session'),
                    _fact_anchor(context, 'host', target, 'host_yields_session'),
                ) if anchor
            ]
            add('session', target,
                {'session_uuid': session_uuid, 'via_exploit': via_exploit,
                 'target': target, 'user': owner or None, 'sid': sid},
                f'{target}:{session_uuid}', method=MSF_SESSION_METHOD, anchors=anchors)
            if owner:
                # Only a descriptor that names an account can substantiate the
                # access claim: the fact is keyed on that account, and without
                # one there is no identity to key it on.
                add('access', target,
                    {'kind': str(record.get('type') or ''), 'user': owner,
                     'via_exploit': via_exploit},
                    f'{target}:{owner}@{session_uuid}', method=MSF_SESSION_METHOD,
                    anchors=anchors)
    elif tool_id == 'nexus.c2.sliver_loot' and result.verification_method == 'sliver_loot_recorded':
        loot = output.get('loot') or {}
        if loot.get('sha256'):
            add('loot', loot.get('name') or loot.get('loot_id'),
                {'sha256': loot['sha256'], 'size': loot.get('size')}, loot.get('name'))
    elif (tool_id == 'nexus.post.shell_exec'
          and result.verification_method in {
              'session_pty_command', 'session_raw_command', 'session_webshell_command'}):
        # A command executed over a registered pty/raw channel is proof that the
        # owned session reaches that target: the peer was bound to the signed
        # scope when the listener accepted it, and the handler only reports the
        # method after ``send``/``capture`` succeeded on a live session. Access is
        # keyed on the target, privilege only on the canonical root identity line,
        # and loot only on flag-shaped tokens (never on an arbitrary file read).
        transport = str(output.get('transport') or 'raw')
        session_ref = str(output.get('session_ref') or '')
        target = str(output.get('target') or '')
        text = str(output.get('output') or '')
        method = result.verification_method
        if target:
            add('access', target,
                {'transport': transport, 'session_ref': session_ref,
                 'target': target, 'session_type': 'pty'},
                f'{target}:{session_ref}', method=method)
        if re.search(r'uid=0\(root\) gid=\d+', text):
            add('privilege', target or session_ref,
                {'uid': 0, 'user': 'root', 'transport': transport,
                 'session_ref': session_ref},
                method=method)
        for flag in FLAG_RE.findall(text):
            add('loot', target or session_ref,
                {'flag': flag, 'service': transport, 'session_ref': session_ref},
                flag, method=method)
    elif (tool_id == 'nexus.session.pty'
          and (arguments or {}).get('action') in {'capture', 'wait'}):
        # The PTY is a command channel, but its capture is local: the deterministic
        # evidence is what the pane printed, not that a remote host answered. Only
        # a flag-shaped token or the canonical root identity line is promoted;
        # everything else stays an observation. ``unverified_observation`` is a
        # ``ToolResult`` status (the handler sets it), not a fact type: the
        # blackboard only accepts verified facts, and inventing a negative row
        # there would let a later turn read "no evidence" as a proven claim.
        session_id = str(output.get('session_id') or 'pty')
        text = str(output.get('output') or '')
        for flag in FLAG_RE.findall(text):
            add('loot', session_id,
                {'flag': flag, 'service': 'pty', 'session_id': session_id},
                flag, method='pty_capture_observed')
        if re.search(r'uid=0\(root\) gid=\d+', text):
            add('privilege', session_id,
                {'uid': 0, 'user': 'root', 'via': 'session.pty',
                 'session_id': session_id},
                method='pty_capture_observed')
    elif (tool_id == 'nexus.post.verify_route'
          and result.verification_method == 'route_probe_ok'):
        # Only a completed probe is a route. The value carries the invocation_id
        # that proved it because the gate and the plan's reconciliation read
        # ``verified_by`` as the route's provenance (DeadDrop P11: the run could
        # not close ``pivot-lan`` because "a tunnel exists" was only an opinion).
        route = output.get('route') if isinstance(output.get('route'), dict) else {}
        from_host = str(route.get('from_host') or '')
        to_host = str(route.get('to_host') or '')
        if from_host and to_host:
            port = route.get('to_port')
            port = port if isinstance(port, int) and 0 < port < 65536 else None
            add('route', route_key(from_host, to_host, port),
                {'from_host': from_host, 'to_host': to_host, 'to_port': port,
                 'method': str(route.get('method') or 'direct'),
                 'forwarder_ref': route.get('forwarder_ref') or None,
                 'verified_by': str(context.invocation_id)},
                route_key(from_host, to_host, port), method='route_probe_ok')
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
                     invocation_id=item['invocation_id'],
                     anchors=item.get('anchors'))
