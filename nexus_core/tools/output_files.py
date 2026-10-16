"""Bounded file-to-parser boundary for tool-generated text artifacts."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from nexus_core.kernel.output_capture import StreamManifest
from nexus_core.kernel.sandbox import SandboxResult
from .execution_contract import record_capture

MAX_OUTPUT_FILE_BYTES = 1_000_000


def read_output_text(path: Path, *, limit: int = MAX_OUTPUT_FILE_BYTES) -> str:
    """Reject symlinks/special files and oversized payloads before parsing.

    Hashes describe observed bytes; an interrupted/oversized read explicitly
    has complete=False. Even handlers with a legacy catch-and-continue path
    retain the failed capture in the invocation contract.
    """
    if limit < 0:
        raise ValueError("output limit must be nonnegative")
    observed = b""
    error: str | None = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError("tool output must be a regular file")
            observed = stream.read(limit + 1)
        if len(observed) > limit:
            error = "OutputLimitExceeded"
            raise OSError("tool output exceeded parser limit")
        return observed.decode("utf-8", errors="replace")
    except OSError as exc:
        error = error or type(exc).__name__
        raise
    finally:
        retained = observed[:limit]
        manifest = StreamManifest(
            len(observed),
            len(retained),
            len(observed) - len(retained),
            hashlib.sha256(observed).hexdigest(),
            hashlib.sha256(retained).hexdigest(),
            len(observed) > limit,
            error is None,
            error,
        )
        record_capture(
            SandboxResult(0 if error is None else 1, "", "", stdout_manifest=manifest),
            source="file",
        )
