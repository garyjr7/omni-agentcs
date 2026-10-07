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
import shutil
from pathlib import Path

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

#: Hard cap on how many bytes of a file the model is ever handed.
WORKSPACE_READ_MAX_BYTES = 65_536
WORKSPACE_READ_DEFAULT_BYTES = WORKSPACE_READ_MAX_BYTES
#: Chunk size of the streaming sha256 pass.
_HASH_CHUNK_BYTES = 65_536


def workspace_root() -> str:
    """Directory the durable handlers write loot/downloads into."""
    return os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())


def workspace_search_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.workspace.search``."""
    return ToolDefinition(
        tool_id="nexus.workspace.search",
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


def workspace_read_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.workspace.read``."""
    return ToolDefinition(
        tool_id="nexus.workspace.read",
        name="Workspace read",
        tenant_id=tenant_id,
        description=(
            "Lee un archivo del workspace del engagement (loot descargado, "
            "wordlists, notas) y devuelve su contenido con sha256. Solo lectura, "
            "confindado al workspace."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 4096},
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
    "resolve_workspace_path",
    "workspace_read_definition",
    "workspace_read_handler",
    "workspace_root",
    "workspace_search_definition",
    "workspace_search_handler",
]
