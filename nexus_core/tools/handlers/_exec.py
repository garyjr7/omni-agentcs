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
) -> SandboxResult:
    """Run ``argv`` in ``sandbox``, normalizing the OCI container signature."""
    if isinstance(sandbox, OCISandbox):
        return await sandbox.run(
            os.getenv(image_env, default_image), argv, timeout_seconds=timeout_seconds
        )
    return await sandbox.run(argv, timeout_seconds=timeout_seconds)


def normalize_targets(values: Iterable[Any] | None, limit: int = MAX_BATCH_TARGETS) -> list[str]:
    """Return a de-duplicated, order-preserving list of non-empty targets.

    Raises ``ValueError`` when nothing usable is left or the batch exceeds the
    hard cap (rather than silently truncating an authorized scope).
    """
    targets: list[str] = []
    for value in values or ():
        text = str(value).strip()
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


def safe_run_id(context: Any, fallback: str = "run") -> str:
    """Return a filesystem-safe run id for durable per-run artifact paths."""
    value = str(getattr(context, "run_id", "") or "").strip()
    value = re.sub(r"[^A-Za-z0-9_-]", "", value)
    return value[:64] or fallback
