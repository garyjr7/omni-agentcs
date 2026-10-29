"""Durable ``nexus.recon.nfs``: exports, listing and reads without root.

The measured dead end (run V9, Hijack): the agent found ``rpcbind``/``nfs`` and
stopped because ``mount -t nfs`` needs root and the sandbox is unprivileged on
purpose. Root is not the only way in: ``showmount -e`` enumerates exports with
no privileges at all, and the libnfs userland clients (``nfs-ls``/``nfs-cat``)
speak the protocol without a kernel mount.

The handler therefore never mounts anything. It answers three actions:

* ``exports`` - ``showmount -e <target>``: the list of exported paths.
* ``list``    - ``nfs-ls nfs://<target><path>``: names inside one export.
* ``read``    - ``nfs-cat nfs://<target><path>/<file>``: bytes of one file.

When the userland client is not installed but the exports are visible, the
answer is ``outcome="partial"`` carrying both facts and the message the
operator needs: the share exists, an unprivileged read is still possible, and
``nexus.system.install_tool`` can install ``libnfs-utils``. A missing
``showmount`` is ``unavailable`` (the run cannot see the surface at all) and
names ``nfs-common`` as the install. Nothing is ever run through a shell: the
binaries are executed directly inside the same sandbox as every other recon
handler.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import (
    OCISandbox,
    sandbox_for_environment,
    sandbox_path,
)

from ._exec import run_in_sandbox

#: Actions the tool declares (the schema publishes exactly these values).
NFS_ACTIONS: tuple[str, ...] = ("exports", "list", "read")

#: Programs the handler may execute. ``showmount`` enumerates; ``nfs-ls`` and
#: ``nfs-cat`` read through libnfs without a kernel mount.
NFS_ALLOWED_PROGRAMS: tuple[str, ...] = ("showmount", "nfs-ls", "nfs-cat")

NFS_DEFAULT_TIMEOUT_SECONDS = 60
NFS_MAX_TIMEOUT_SECONDS = 300

#: Cap on listing lines and read bytes that travel back in the observation.
NFS_MAX_LISTING_LINES = 500
NFS_MAX_READ_BYTES = 200_000

#: The message the operator needs when the exports are visible but the
#: userland client is missing (the plan's FIX 2 wording).
NFS_MOUNT_GUIDANCE = (
    "Directorio NFS detectado. Solicita al humano que monte el recurso o usa "
    "`nfs-ls` si está disponible."
)

#: What to do when the userland client ran and the server refused the read.
NFS_FAILED_HINT = (
    "El cliente userland arrancó pero la lectura no se completó. Lee el `stderr`: "
    "`permission denied`/`access denied` significa que el export restringe tu "
    "cliente (prueba desde otro host o pide al humano que monte el recurso); "
    "`no such file` significa que `path` no es un export de la lista. Si el "
    "vector está cerrado, registra un barrier con nexus.knowledge.record_fact "
    "(key \"<host>:2049\") y pivota."
)

#: Install hint appended when the required binary is absent from the sandbox.
NFS_INSTALL_GUIDANCE = {
    "showmount": (
        "Falta `showmount` en el sandbox. Instálalo con "
        "nexus.system.install_tool(tool_name=\"nfs-common\") (el operador "
        "aprueba el comando) y reintenta."
    ),
    "nfs-ls": (
        "Falta `nfs-ls` en el sandbox. Instala el cliente userland con "
        "nexus.system.install_tool(tool_name=\"libnfs-utils\") para leer el "
        "export sin root."
    ),
    "nfs-cat": (
        "Falta `nfs-cat` en el sandbox. Instala el cliente userland con "
        "nexus.system.install_tool(tool_name=\"libnfs-utils\") para leer el "
        "export sin root."
    ),
}


def resolve_program(program: str) -> str:
    """Absolute path of *program* when the sandbox PATH hides the sbin dirs.

    The measured surprise on this Kali host: ``showmount`` lives in
    ``/usr/sbin`` and the sandbox PATH is ``/usr/local/bin:/usr/bin:/bin``, so a
    perfectly installed ``nfs-common`` was reported as missing. Resolution uses
    the sandbox PATH *plus* the sbin directories, and the resolved path is what
    the sandbox allowlist receives, so the same binary the operator sees is the
    one that runs. The OCI image is untouched (its paths are its own).
    """
    directories = f"{sandbox_path()}:/usr/sbin:/sbin:/usr/local/sbin"
    found = shutil.which(program, path=directories)
    return found or program


def _sandbox(workspace_root: str) -> tuple[Any, dict[str, str]]:
    """Build the sandbox and the program map (bare name -> argv[0] to run)."""
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=NFS_ALLOWED_PROGRAMS)
    programs = {name: name for name in NFS_ALLOWED_PROGRAMS}
    if isinstance(sandbox, OCISandbox):
        return sandbox, programs
    programs = {name: resolve_program(name) for name in NFS_ALLOWED_PROGRAMS}
    if any(path != name for name, path in programs.items()):
        sandbox = sandbox_for_environment(
            workspace_root, allowed_programs=tuple(dict.fromkeys(programs.values()))
        )
    return sandbox, programs


def _validate_text(value: Any, name: str, *, max_length: int) -> str:
    """Trimmed text argument; empty, over-long or control-bearing is refused."""
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    if len(text) > max_length:
        raise ValueError(f"{name} is too long")
    if any(ord(char) < 0x20 for char in text):
        raise ValueError(f"{name} contains control characters")
    return text


def _export_path(value: Any) -> str:
    """Normalize an export path to ``/path`` (a bare ``srv/nfs`` is accepted)."""
    text = _validate_text(value, "path", max_length=1024)
    if not text.startswith("/"):
        text = "/" + text
    return text


def _nfs_url(target: str, path: str, file: str | None = None) -> str:
    """``nfs://host/export[/file]`` URL the libnfs clients understand."""
    url = f"nfs://{target}{path}"
    if file:
        url = f"{url.rstrip('/')}/{file.lstrip('/')}"
    return url


def parse_exports(stdout: str) -> list[dict[str, Any]]:
    """Parse ``showmount -e`` into ``[{"path": …, "clients": […]}]``.

    The first line is the ``Export list for <host>:`` header (older builds print
    it with a trailing space). Blank lines and anything before the header are
    ignored, so a warning printed by rpcbind never becomes an export.
    """
    entries: list[dict[str, Any]] = []
    header_seen = False
    for raw in str(stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not header_seen:
            if line.lower().startswith("export list for"):
                header_seen = True
                continue
            # A build without the header still prints ``/path client`` lines.
            if not line.startswith("/"):
                continue
        parts = line.split()
        path = parts[0]
        if not path.startswith("/"):
            continue
        entries.append({"path": path, "clients": parts[1:]})
    return entries


async def _exports(
    sandbox: Any, target: str, timeout_seconds: int, *, program: str = "showmount"
) -> tuple[Any | None, list[dict[str, Any]]]:
    """Run ``showmount -e``; return ``(result or None, exports)``.

    ``None`` means the binary is not in the sandbox: the caller turns that into
    ``unavailable`` with the install hint instead of a phantom empty list.
    """
    try:
        result = await run_in_sandbox(
            sandbox,
            [program, "-e", target],
            timeout_seconds=timeout_seconds,
            image_env="NEXUS_NFS_IMAGE",
            default_image="python:3.12-alpine",
        )
    except (FileNotFoundError, PermissionError):
        return None, []
    return result, parse_exports(result.stdout)


def nfs_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.nfs``."""
    return ToolDefinition(
        tool_id="nexus.recon.nfs",
        effect="read_only",
        name="NFS recon (no root)",
        tenant_id=tenant_id,
        description=(
            "Enumera exports NFS con showmount -e y los lee sin root con "
            "nfs-ls/nfs-cat (libnfs). Usa action=exports, list (path) o read "
            "(path + file). Sin montaje del kernel."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "action": {"type": "string", "enum": list(NFS_ACTIONS)},
                "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                "file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": NFS_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        scope_required=True,
        scope_target_field="target",
        required_permissions=["execute:tool:nexus.recon.nfs"],
        timeout_seconds=NFS_MAX_TIMEOUT_SECONDS + 60,
        max_output_bytes=2_000_000,
    )


async def nfs_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Enumerate or read an NFS export without mounting it."""
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    action = str(arguments.get("action") or "exports").strip().lower()
    if action not in NFS_ACTIONS:
        raise ValueError(f"unsupported nfs action: {action!r}")
    path = _export_path(arguments["path"]) if arguments.get("path") else ""
    if action in {"list", "read"} and not path:
        raise ValueError(f"action={action} requires path (the NFS export)")
    file = _validate_text(arguments.get("file"), "file", max_length=1024) if action == "read" else ""
    if action == "read" and not file:
        raise ValueError("action=read requires file")

    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NFS_MAX_TIMEOUT_SECONDS,
        max(5, int(requested) if requested else NFS_DEFAULT_TIMEOUT_SECONDS),
    )
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox, programs = _sandbox(workspace_root)

    evidence: dict[str, Any] = {
        "action": action,
        "target": target,
        "noise_level": "low",
        "timeout_seconds": timeout_seconds,
        **({"path": path} if path else {}),
        **({"file": file} if file else {}),
    }

    if action == "exports":
        result, exports = await _exports(
            sandbox, target, timeout_seconds, program=programs["showmount"]
        )
        if result is None:
            return ToolResult(
                output={
                    "error": "showmount is not available in the sandbox",
                    "target": target,
                    "guidance": NFS_INSTALL_GUIDANCE["showmount"],
                },
                verified=False,
                outcome="unavailable",
                verification_method="nfs_showmount_unavailable",
                evidence=evidence,
            )
        return _exports_result(result, exports, evidence, target=target)

    program = "nfs-ls" if action == "list" else "nfs-cat"
    url = _nfs_url(target, path, file if action == "read" else None)
    try:
        result = await run_in_sandbox(
            sandbox,
            [programs[program], url],
            timeout_seconds=timeout_seconds,
            image_env="NEXUS_NFS_IMAGE",
            default_image="python:3.12-alpine",
        )
    except (FileNotFoundError, PermissionError):
        # The userland client is missing: report what *is* visible (the exports)
        # plus the message, never a dead end. This is the plan's FIX 2 contract.
        _, exports = await _exports(
            sandbox, target, timeout_seconds, program=programs["showmount"]
        )
        evidence["exports"] = exports
        evidence["partial_reason"] = f"{program}_missing"
        return ToolResult(
            output={
                "target": target,
                "action": action,
                "path": path,
                "exports": exports,
                "partial": True,
                # Machine-readable reason first (the loop and the operator read
                # it), then the human message and the one action that unblocks
                # the vector. Measured in Hijack v3: the model had this answer
                # and still burned 23 pyNfsClient calls instead of installing
                # the client.
                "error": "userland_client_missing",
                "message": NFS_MOUNT_GUIDANCE,
                "hint": NFS_INSTALL_GUIDANCE[program],
                "guidance": NFS_INSTALL_GUIDANCE[program],
            },
            verified=False,
            outcome="partial",
            verification_method=f"nfs_{program.replace('-', '_')}_missing",
            evidence=evidence,
        )

    if result.timed_out:
        return ToolResult(
            output={"error": f"{program} timed out", "target": target, "action": action},
            verified=False,
            outcome="timeout",
            verification_method=f"nfs_{program.replace('-', '_')}_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    if result.exit_code != 0:
        # The client ran and the server refused (export restricted to another
        # host, stale handle...). The exports travel with the refusal so the
        # model can see what it *can* reach, and the outcome stays partial.
        _, exports = await _exports(
            sandbox, target, timeout_seconds, program=programs["showmount"]
        )
        evidence["exports"] = exports
        evidence["exit_code"] = result.exit_code
        evidence["partial_reason"] = f"{program}_failed"
        return ToolResult(
            output={
                "target": target,
                "action": action,
                "path": path,
                "exports": exports,
                "partial": True,
                "error": "mount_failed",
                "message": NFS_MOUNT_GUIDANCE,
                "hint": NFS_FAILED_HINT,
                "stdout": result.stdout[:2_000],
                "stderr": result.stderr[:2_000],
            },
            verified=False,
            outcome="partial",
            verification_method=f"nfs_{program.replace('-', '_')}_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if action == "list":
        lines = [line for line in str(result.stdout or "").splitlines() if line.strip()]
        evidence["entries_total"] = len(lines)
        evidence["entries_truncated"] = len(lines) > NFS_MAX_LISTING_LINES
        if not lines:
            # An empty listing is a real observation, not a success with nothing
            # in it: the model must not read it as "there is something here".
            return ToolResult(
                output={
                    "target": target,
                    "action": action,
                    "path": path,
                    "entries": [],
                    "count": 0,
                    "message": (
                        "El export está vacío: el cliente userland leyó el directorio y "
                        "no devolvió entradas. Prueba otro export de la lista o lee un "
                        "fichero concreto con action=read."
                    ),
                },
                verified=True,
                outcome="negative",
                verification_method="nfs_listing_empty",
                evidence=evidence,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        return ToolResult(
            output={
                "target": target,
                "action": action,
                "path": path,
                "entries": lines[:NFS_MAX_LISTING_LINES],
                "count": len(lines[:NFS_MAX_LISTING_LINES]),
                "truncated": len(lines) > NFS_MAX_LISTING_LINES,
            },
            verified=True,
            verification_method="nfs_listing_parsed",
            evidence=evidence,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    content = str(result.stdout or "")
    truncated = len(content.encode("utf-8", "replace")) > NFS_MAX_READ_BYTES
    evidence["file"] = file
    evidence["bytes_total"] = len(content.encode("utf-8", "replace"))
    evidence["read_truncated"] = truncated
    return ToolResult(
        output={
            "target": target,
            "action": action,
            "path": path,
            "file": file,
            "preview": content[:NFS_MAX_READ_BYTES],
            "truncated": truncated,
        },
        verified=bool(content) and not truncated,
        outcome="" if content else "negative",
        verification_method="nfs_file_read" if content else "nfs_file_empty",
        evidence=evidence,
        exit_code=result.exit_code,
        stdout=content[:NFS_MAX_READ_BYTES],
        stderr=result.stderr,
    )


#: stderr fragments that mean "nothing is listening", not "the answer is no".
#: ``showmount`` prints these when rpcbind/mountd are closed or filtered, which
#: is an infrastructure answer (``unavailable``), never an empty export table
#: (``negative``) -the V1-16 boundary between "could not look" and "looked".
_NFS_UNREACHABLE_HINTS: tuple[str, ...] = (
    "clnt_create",
    "unable to receive",
    "program not registered",
    "rpc: timed out",
    "no route to host",
    "connection refused",
)


def _unreachable(result: Any) -> bool:
    text = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    return any(hint in text for hint in _NFS_UNREACHABLE_HINTS)


def _exports_result(
    result: Any,
    exports: list[dict[str, Any]],
    evidence: dict[str, Any],
    *,
    target: str,
) -> ToolResult:
    """Turn one ``showmount -e`` run into the observable exports result.

    Three answers are kept distinct, because they tell the agent to do different
    things: the command ran and the table is empty (``verified``: this host
    exports nothing), the RPC layer refused (*unavailable*: rpcbind/mountd are
    closed or filtered, pivot or retry later) and any other failure
    (``negative``, with the real stderr).
    """
    evidence["exports_total"] = len(exports)
    evidence["exit_code"] = result.exit_code
    ok = result.exit_code == 0
    unreachable = not ok and _unreachable(result)
    evidence["reachable"] = not unreachable
    output: dict[str, Any] = {
        "target": target,
        "action": "exports",
        "exports": exports,
        "count": len(exports),
        "stdout": result.stdout[:4_000],
        "stderr": result.stderr[:2_000],
    }
    if ok and exports:
        # The export table is the *surface*, not the contents: say what the next
        # call is and what it needs, so a success here is never read as "NFS
        # enumerated" (Hijack v3 spent 23 calls importing pyNfsClient).
        output["next_steps"] = [
            "Para ver el contenido de un export: "
            'nexus.recon.nfs(target=..., action="list", path="<export>").',
            "action=list usa el cliente userland `nfs-ls` (paquete `libnfs-utils`); "
            "si falta, el propio resultado lo dice con error=userland_client_missing.",
        ]
    return ToolResult(
        output=output,
        verified=ok,
        outcome="" if ok else ("unavailable" if unreachable else "negative"),
        verification_method=(
            "nfs_exports_parsed" if ok
            else "nfs_exports_unavailable" if unreachable
            else "nfs_exports_failed"
        ),
        evidence=evidence,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "NFS_ACTIONS",
    "NFS_ALLOWED_PROGRAMS",
    "NFS_INSTALL_GUIDANCE",
    "NFS_MOUNT_GUIDANCE",
    "nfs_definition",
    "nfs_handler",
    "parse_exports",
    "resolve_program",
]
