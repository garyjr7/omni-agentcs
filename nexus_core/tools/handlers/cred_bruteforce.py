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
  difference (measured in Brute It, iteration 12);
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
from urllib.parse import urlsplit

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.kernel.secret_store import DEFAULT_SECRET_KIND, default_secret_store

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
CRED_TOOL_TIMEOUT_SECONDS = 900
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
WORDLIST_ROOTS_ENV = "NEXUS_WORDLIST_ROOTS"
DEFAULT_WORDLIST_ROOTS = ("/usr/share/wordlists", "/usr/share/seclists", "/opt/seclists")
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
                "password_file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                # No ``maximum``: an auditor with a 14M-word list is entitled to
                # run it. The caps are the operator's (scope/RoE) and the run's
                # budget, not a number baked into the contract.
                "max_attempts": {"type": "integer", "minimum": 1},
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


def _truncate_wordlist(source: str, dest: str, max_attempts: int | None) -> int:
    """Copy the non-empty lines of ``source`` into ``dest``; return the count.

    ``None`` means *the whole list*: no artificial attempt cap, so a 14M-word
    dictionary runs as far as the tool's time budget and the run's budget allow.
    The copy is streamed, so the size of the source is not work and the old
    16 MB ceiling (which rejected the one list an operator always has, measured
    in ``run_7661dda481784eebb17a76e037c5722b``) stays gone.
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
            if max_attempts is not None and count >= max_attempts:
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
            raise ValueError(
                "form_url must be the login path ('/admin/') or an http/https URL"
            )
        parts = urlsplit(text)
        if parts.query:
            raise ValueError(
                "form_url must not carry a query string; pass the form fields in "
                "form_params"
            )
        host = str(parts.hostname or "")
        try:
            port = parts.port
        except ValueError as exc:  # ``http://host:notaport/``
            raise ValueError("form_url carries an invalid port") from exc
        secure = scheme == "https"
        path = parts.path or "/"
    else:
        path = text
    if not path.startswith("/"):
        path = "/" + path
    return path, host, port, secure


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
        raise ValueError("form_url must be the login path, starting with '/'")
    if ":" in path or any(char.isspace() for char in path):
        raise ValueError("form_url must not contain ':' or whitespace")
    params = _validate_text(form_params, "form_params", max_length=512)
    if "^USER^" not in params or "^PASS^" not in params:
        raise ValueError(
            "form_params must carry hydra's placeholders, e.g. "
            "'user=^USER^&pass=^PASS^&submit=Login'"
        )
    if ":" in params or any(char.isspace() for char in params):
        raise ValueError("form_params must not contain ':' or whitespace")
    failure = _validate_text(failure_string, "failure_string", max_length=200)
    if ":" in failure:
        raise ValueError(
            "failure_string must not contain ':' (it separates hydra's conditions)"
        )
    return f"{path}:{params}:F={failure}"


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
            value={"reason": reason, **(detail or {})},
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
        raise ValueError(f"unsupported service: {service!r}")
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
    if service in CRED_FORM_SERVICES:
        form_path, form_host, form_port, secure = _normalize_form_url(
            arguments.get("form_url")
        )
        form_spec = _form_spec(
            form_path, arguments.get("form_params"), arguments.get("failure_string")
        )

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
        raise ValueError("port out of range")
    secure = (secure and same_host) or port in CRED_SSL_PORTS
    # No cap of the handler's own: ``max_attempts`` cuts the list only when the
    # caller asks for it, and ``timeout_seconds`` is the caller's or the budget the
    # tool's contract publishes. The TCP script keeps its own (smaller) budget
    # because it is a python probe, not a hydra sweep.
    requested_attempts = arguments.get("max_attempts")
    max_attempts = int(requested_attempts) if requested_attempts else None
    requested_timeout = arguments.get("timeout_seconds")
    default_timeout = (
        CRED_DEFAULT_TIMEOUT_SECONDS
        if service in {"tcp", "telnet"}
        else CRED_SWEEP_TIMEOUT_SECONDS
    )
    timeout_seconds = int(requested_timeout) if requested_timeout else default_timeout

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
        "found_count": len(credentials),
        "noise_level": "medium",
        "timeout_seconds": timeout_seconds,
    }
    if form_spec:
        # The route, never the template: the form params carry the operator's
        # passwords only as hydra placeholders, but the path is what the board
        # needs to tie the attempt to the endpoint.
        evidence["form_url"] = form_path

    # V1-29: the plaintext is stored, never forwarded. What the loop, the
    # blackboard and the prompt see is the handle.
    stored = store_discovered_credentials(credentials, tenant_id=context.tenant_id)
    evidence["secret_refs"] = [entry["secret_ref"] for entry in stored if entry.get("secret_ref")]
    stdout = _scrub_plaintext(result.stdout or "", credentials)
    stderr = _scrub_plaintext(result.stderr or "", credentials)

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
                    "timeout_seconds, parte la lista en trozos o cambia de vector."
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
    negative = not stored and not result.timed_out
    verdict = _hydra_verdict(combined) if negative else ""
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
    result_output: dict[str, Any] = {
        "target": target,
        "service": service,
        "port": port,
        "username": username,
        "attempts": attempts,
        "valid_credentials": stored,
    }
    if negative:
        result_output["message"] = (
            "Hydra completó el ataque sin encontrar credenciales válidas"
            if completed_sweep
            else "Hydra terminó el barrido sin credenciales válidas"
        )
        if verdict:
            result_output["hydra_verdict"] = verdict
    return ToolResult(
        output=result_output,
        verified=verified,
        outcome="" if verified else ("negative" if negative else ""),
        verification_method="cred_bruteforce_completed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=stdout,
        stderr=stderr,
    )
