"""Bounded synchronous diagnostics for local version commands (never a shell)."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Sequence

PROBE_OUTPUT_LIMIT = 65536


def bounded_probe(argv: Sequence[str], *, timeout: float = 10.0) -> tuple[int, str]:
    """Drain merged pipes incrementally; cap retained bytes and total runtime.

    Oversized output fails verification even when the signature appeared first.
    The process group is reaped on timeout, including inherited pipe holders.
    """
    if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
        return 127, "invalid probe argv"
    if not math.isfinite(timeout) or timeout <= 0:
        return 124, "invalid probe timeout"
    retained = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with subprocess.Popen(
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        ) as process:
            assert process.stdout is not None
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(argv, timeout)
                        for key, _ in selector.select(min(remaining, 0.1)):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            total += len(chunk)
                            retained.extend(chunk[: max(0, PROBE_OUTPUT_LIMIT - len(retained))])
                    code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            finally:
                # Also clean descendants that closed their pipes before the parent.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
    except subprocess.TimeoutExpired:
        return 124, "probe timed out"
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"probe unavailable ({type(exc).__name__})"
    if total > PROBE_OUTPUT_LIMIT:
        return 125, "probe output exceeded limit"
    return code, retained.decode("utf-8", errors="replace").strip()
