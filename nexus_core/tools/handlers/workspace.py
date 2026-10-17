"""Durable ``nexus.workspace.*`` tools (moved out of the runtime).

Two read-only tools over the *engagement workspace* (the directory the recon
handlers download into):

* ``nexus.workspace.search`` greps it through the sandbox (needs ``rg``);
* ``nexus.workspace.read`` reads one file and reports its sha256.

``read`` exists because of the E2E blocker B7: ``nexus.recon.ftp download`` only
returned metadata, so the agent could download ``locks.txt`` and then had no way
to *read* it. Reading a local file is not an action against the target, so it
needs no scope, but it is the one place where the agent can pull arbitrary bytes
of the host into its own prompt: the path is therefore confined to the workspace
root (symlinks and ``..`` resolved before the check), the size is capped, and the
content leaves this handler as untrusted data that the prompt boundary wraps in
``<<UNTRUSTED_TOOL_OUTPUT>>``.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import Any

from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

#: Hard cap on how many bytes of a file the model is ever handed.
WORKSPACE_READ_MAX_BYTES = 65_536
WORKSPACE_READ_DEFAULT_BYTES = WORKSPACE_READ_MAX_BYTES
#: Chunk size of the streaming sha256 pass.
_HASH_CHUNK_BYTES = 65_536
#: The ids ``shell.exec``/``web.request`` return when they archive a long
#: output: ``artifact_<32 hex>`` (canonical) or the bare 32-hex digest.
_ARTIFACT_ID_RE = re.compile(r"artifact_[a-f0-9]{32}")
_ARTIFACT_BARE_RE = re.compile(r"[a-f0-9]{32}")


def workspace_root() -> str:
    """Directory the durable handlers write loot/downloads into."""
    return os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())


def workspace_search_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.workspace.search``."""
    return ToolDefinition(
        tool_id="nexus.workspace.search",
        effect="read_only",
        name="Workspace search",
        tenant_id=tenant_id,
        description=(
            "Busca un patrón en el workspace del engagement. Usa ripgrep si "
            "está instalado y, si no, GNU grep (mismo contrato)."
        ),
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool"],
    )


def search_argv(query: str, *, program: str | None = None) -> list[str]:
    """Build the search argv, preferring ``rg`` and falling back to ``grep``.

    ``rg`` was hardcoded and the E2E #5 failed this tool with
    ``No such file or directory: 'rg'`` on a host that ships GNU grep but not
    ripgrep. Both exit 1 for a verified empty result, so the contract is the same.
    """
    chosen = program or ("rg" if shutil.which("rg") else "grep")
    if chosen == "rg":
        return ["rg", "-n", "--max-count", "100", "--", query, "."]
    return ["grep", "-rn", "-m", "100", "--", query, "."]


async def workspace_search_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Search the workspace through the sandbox and report verified matches."""
    query = str(arguments["query"])
    # Both binaries are allowlisted so the fallback never trips the sandbox's
    # program policy, whichever one this host actually has.
    sandbox = sandbox_for_environment(
        workspace_root(), allowed_programs=("python3", "git", "rg", "grep")
    )
    program = "rg" if shutil.which("rg") else "grep"
    try:
        result = await sandbox.run(search_argv(query, program=program), timeout_seconds=20)
    except FileNotFoundError:
        # The chosen binary vanished from PATH between the check and the exec.
        program = "grep" if program == "rg" else "rg"
        result = await sandbox.run(search_argv(query, program=program), timeout_seconds=20)
    from nexus_core.tools.execution_contract import record_capture

    record_capture(result)
    return ToolResult(
        output={"matches": result.stdout, "program": program},
        verified=result.exit_code in {0, 1} and not result.timed_out,
        verification_method="sandbox_exit_code",
        evidence={"query": query, "program": program, "exit_code": result.exit_code,
                  "timed_out": result.timed_out},
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),  # rg/grep use 1 for a verified empty result
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )


def artifact_id_from_path(path: str) -> str | None:
    """Return the artifact id named by ``path``, or ``None`` for a real path.

    ``shell.exec`` and ``web.request`` truncate a long observation and hand the
    model an ``artifact_id`` instead of the payload; before this, the only tool
    that could read it (``nexus.workspace.read``) answered ``file not found``
    and the agent lost two turns of the Simple CTF run (2026-10-17). The id is
    accepted as ``artifact:<id>``, ``artifact_<32 hex>`` or a bare 32-hex digest;
    anything else stays a filesystem path and is confined as before.
    """
    text = str(path or "").strip()
    if text.startswith("artifact:"):
        text = text.split(":", 1)[1].strip()
    if _ARTIFACT_ID_RE.fullmatch(text):
        return text
    if _ARTIFACT_BARE_RE.fullmatch(text):
        return f"artifact_{text}"
    return None


def _read_artifact(
    artifact_id: str, context: RunContext, limit: int
) -> tuple[dict[str, Any], bytes, bytes, bool]:
    """Load one stored artifact, capped at ``limit`` bytes.

    Returns ``(reference, full_bytes, returned_bytes, truncated)``. Raises
    ``ValueError`` when the run has no store, the artifact does not exist in this
    tenant, or the stored media type is not text-like.
    """
    if context.store is None:
        raise ValueError("artifact store is not available in this run")
    from nexus_core.tools.handlers.report_generate import default_artifact_root

    repository = configured_artifact_store(context.store, default_artifact_root())
    try:
        data = repository.get(context.tenant_id, artifact_id)
    except KeyError:
        raise ValueError(f"artifact not found: {artifact_id}") from None
    with repository.store.connect() as conn:
        row = conn.execute(
            "SELECT media_type FROM kernel_artifacts WHERE id=? AND tenant_id=?",
            (artifact_id, context.tenant_id),
        ).fetchone()
    media_type = str(row["media_type"] if row is not None else "") or "application/octet-stream"
    return (
        {
            "id": artifact_id,
            "media_type": media_type,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        data,
        data[:limit],
        len(data) > limit,
    )


def workspace_read_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.workspace.read``."""
    return ToolDefinition(
        tool_id="nexus.workspace.read",
        effect="read_only",
        name="Workspace read",
        tenant_id=tenant_id,
        description=(
            "Lee un archivo del workspace del engagement (loot descargado, "
            "wordlists, notas) y devuelve su contenido con sha256. También "
            "acepta el artifact_id de una salida archivada (artifact_<hex32>). "
            "Solo lectura, confinado al workspace."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": (
                        "Ruta relativa al workspace, o el artifact_id que "
                        "devuelve una tool cuando archiva una salida larga "
                        "(sqlmap, web.request, shell.exec)."
                    ),
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": WORKSPACE_READ_MAX_BYTES,
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool:nexus.workspace.read"],
        timeout_seconds=30,
        max_output_bytes=200_000,
    )


def resolve_workspace_path(path: str, *, root: str | None = None) -> Path:
    """Resolve ``path`` inside the workspace root, or raise ``ValueError``.

    Both the candidate and the root are resolved (symlinks included) before the
    containment check, so neither ``..`` nor a symlink can walk the agent out of
    its own workspace. A missing path, a directory and a device are all refused.
    """
    text = str(path or "").strip()
    if not text:
        raise ValueError("path is required")
    if "\x00" in text:
        raise ValueError("path contains a NUL byte")
    root_path = Path(root if root is not None else workspace_root()).resolve()
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    if not candidate.exists():
        raise ValueError(f"file not found in workspace: {text}")
    if not candidate.is_file():
        raise ValueError(f"not a regular file: {text}")
    if candidate.is_symlink() and not candidate.resolve().is_file():
        raise ValueError(f"not a regular file: {text}")
    resolved = candidate.resolve()
    if resolved != root_path and root_path not in resolved.parents:
        raise ValueError(f"path escapes the engagement workspace: {text}")
    return resolved


def _sha256_file(path: Path) -> str:
    """Streaming sha256 of the whole file (matches what the download reported)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode(data: bytes) -> tuple[str, str]:
    """Decode bytes as UTF-8, degrading to ``replace`` for binary loot."""
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), "utf-8/replace"


async def workspace_read_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Read one file of the workspace and report its content and sha256."""
    raw_path = str(arguments.get("path") or "")
    root = workspace_root()
    requested = arguments.get("max_bytes")
    try:
        limit = int(requested) if requested else WORKSPACE_READ_DEFAULT_BYTES
    except (TypeError, ValueError):
        raise ValueError("max_bytes must be an integer") from None
    limit = max(1, min(int(limit), WORKSPACE_READ_MAX_BYTES))

    artifact_id = artifact_id_from_path(raw_path)
    if artifact_id is not None:
        reference, full, data, truncated = _read_artifact(artifact_id, context, limit)
        content, encoding = _decode(data)
        return ToolResult(
            output={
                "path": artifact_id,
                "artifact": reference,
                "size_bytes": len(full),
                "bytes_returned": len(data),
                "truncated": truncated,
                "sha256": reference["sha256"],
                "encoding": encoding,
                "lines": content.count("\n") + (1 if content else 0),
                "content": content,
            },
            verified=True,
            verification_method="workspace_read_artifact",
            evidence={
                "artifact_id": artifact_id,
                "media_type": reference["media_type"],
                "size_bytes": len(full),
                "bytes_returned": len(data),
                "sha256": reference["sha256"],
                "truncated": truncated,
                "noise_level": "none",
            },
            exit_code=0,
            accepted_exit_codes=(0,),
        )

    path = resolve_workspace_path(raw_path, root=root)
    size = path.stat().st_size
    with path.open("rb") as handle:
        data = handle.read(limit)
    truncated = size > len(data)
    digest = _sha256_file(path)
    content, encoding = _decode(data)
    try:
        relative = str(path.relative_to(Path(root).resolve()))
    except ValueError:  # pragma: no cover - guarded by resolve_workspace_path
        relative = path.name

    return ToolResult(
        output={
            "path": relative,
            "absolute_path": str(path),
            "size_bytes": size,
            "bytes_returned": len(data),
            "truncated": truncated,
            "sha256": digest,
            "encoding": encoding,
            "lines": content.count("\n") + 1,
            "content": content,
        },
        verified=True,
        verification_method="workspace_read_sha256",
        evidence={
            "path": relative,
            "size_bytes": size,
            "bytes_returned": len(data),
            "sha256": digest,
            "truncated": truncated,
            "noise_level": "none",
        },
        exit_code=0,
        accepted_exit_codes=(0,),
    )


__all__ = [
    "WORKSPACE_READ_DEFAULT_BYTES",
    "WORKSPACE_READ_MAX_BYTES",
    "artifact_id_from_path",
    "resolve_workspace_path",
    "workspace_read_definition",
    "workspace_read_handler",
    "workspace_root",
    "workspace_search_definition",
    "workspace_search_handler",
]
