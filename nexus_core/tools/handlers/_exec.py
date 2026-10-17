"""Shared sandbox plumbing for the durable recon/web handlers.

Every offensive handler runs its binary through ``sandbox_for_environment`` and
never spawns a process on its own (the unit tests assert that
``asyncio.create_subprocess_exec`` is untouched). This module centralizes the
program allowlist and the OCI/argv normalization so the four handlers stay
identical in their execution contract.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from typing import Any

from nexus_core.kernel.sandbox import OCISandbox, SandboxResult
from nexus_core.tools.execution_contract import record_capture, validate_target
from nexus_core.provisioner.binaries import BinaryIdentity, IdentityCheck, classify_identity

#: Programs the durable recon/web handlers are allowed to execute.
RECON_ALLOWED_PROGRAMS: tuple[str, ...] = (
    "python3",
    "git",
    "rg",
    "nmap",
    "subfinder",
    "httpx",
    "nuclei",
    "ffuf",
)

#: Hard cap on how many targets one batch tool accepts (argv transport).
MAX_BATCH_TARGETS = 500


async def run_in_sandbox(
    sandbox: Any,
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    image_env: str,
    default_image: str,
    extra_env: dict[str, str] | None = None,
    input_data: bytes | str | None = None,
) -> SandboxResult:
    """Run ``argv`` in ``sandbox``, normalizing the OCI container signature.

    ``extra_env`` passes tool-specific variables to the child (for example
    ``KRB5CCNAME`` for the Kerberos tooling). The sandbox still refuses to let a
    handler override its own controls (PATH/HOME/XDG).
    """
    args: tuple[Any, ...] = (argv,)
    if isinstance(sandbox, OCISandbox):
        args = (os.getenv(image_env, default_image), argv)
    options: dict[str, Any] = {"timeout_seconds": timeout_seconds}
    if extra_env:
        options["extra_env"] = extra_env
    if input_data is not None:
        options["input_data"] = input_data
    result: SandboxResult = await sandbox.run(*args, **options)
    record_capture(result)
    return result


def normalize_targets(values: Iterable[Any] | None, limit: int = MAX_BATCH_TARGETS) -> list[str]:
    """Return a de-duplicated, order-preserving list of non-empty targets.

    Raises ``ValueError`` when nothing usable is left or the batch exceeds the
    hard cap (rather than silently truncating an authorized scope).
    """
    if isinstance(values, (str, bytes, dict)):
        raise ValueError("targets must be a collection of strings")
    targets: list[str] = []
    for value in values or ():
        text = validate_target(value)
        if text and text not in targets:
            targets.append(text)
    if not targets:
        raise ValueError("at least one target is required")
    if len(targets) > limit:
        raise ValueError(f"too many targets: {len(targets)} > {limit}")
    return targets


def append_repeated(flag: str, values: Sequence[str]) -> list[str]:
    """Build ``-flag v1 -flag v2 ...`` (the argv batch transport)."""
    argv: list[str] = []
    for value in values:
        argv.extend([flag, value])
    return argv


async def probe_identity_in_sandbox(
    sandbox: Any,
    identity: BinaryIdentity,
    *,
    timeout_seconds: float = 10.0,
    image_env: str,
    default_image: str,
) -> IdentityCheck:
    """Verify a binary's identity *through the sandbox* (never a raw spawn).

    Used by handlers to tell "the binary is the wrong one" apart from "the tool
    ran but produced nothing usable" without breaking the invariant that only
    the sandbox starts processes.
    """
    argv = [identity.name, *identity.version_argv]
    try:
        result = await run_in_sandbox(
            sandbox, argv, timeout_seconds=timeout_seconds,
            image_env=image_env, default_image=default_image,
        )
    except (OSError, RuntimeError, ValueError):
        return classify_identity(identity, path=identity.name, present=False, output="")
    present = result.exit_code is not None and result.exit_code != 127
    output = f"{result.stdout}\n{result.stderr}"
    return classify_identity(identity, path=identity.name, present=present, output=output, exit_code=result.exit_code,
                             complete=not (result.timed_out or result.cancelled) and all(
                                 m is None or (m.complete and not m.truncated and not m.error)
                                 for m in (result.stdout_manifest, result.stderr_manifest)))


def safe_run_id(context: Any, fallback: str = "run") -> str:
    """Return a filesystem-safe run id for durable per-run artifact paths."""
    value = str(getattr(context, "run_id", "") or "").strip()
    value = re.sub(r"[^A-Za-z0-9_-]", "", value)
    return value[:64] or fallback
