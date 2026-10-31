"""One semantic signature for a governed call, shared by every dedup layer.

Three places used to decide \"is this the same work?\" with three different keys:
the invocation journal (raw arguments + phase + objective), the ReAct repeat
guard (raw redacted arguments) and the background task manager (arguments with
``timeout_seconds`` ignored). The measured consequence on 2026-10-31 was a
``nmap full_tcp`` launched four times in the same run: the first with a timeout
argument and the rest without, one direct and three from the background manager,
each layer believing it was a different intent.

The rule here is deliberately narrow: only arguments that tune *how long the
engine waits* are incidental. Target, ports, profile, scripts, wordlist, share,
module and CVE remain part of the signature, so a genuinely different scan is a
different intent and still runs.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

#: Arguments that describe the *wrapper* (how long to wait, how to schedule)
#: rather than the work done on the target. The engine's own timeout is already
#: enforced per tool contract, so two calls that differ only here are one scan.
INCIDENTAL_ARGUMENT_KEYS = frozenset(
    {
        "timeout_seconds",
        "timeout",
        "poll_seconds",
        "wait_seconds",
        "background",
        "async",
        "run_in_background",
    }
)


def semantic_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Arguments with incidental and empty values removed (never mutates input).

    Empty values are equivalent to absent for every handler in the catalog, so
    dropping them keeps an explicit ``""`` from looking like a new intent.
    """
    cleaned: dict[str, Any] = {}
    for key, value in dict(arguments or {}).items():
        name = str(key)
        if name in INCIDENTAL_ARGUMENT_KEYS:
            continue
        if value is None or value == "" or value in ([], {}):
            continue
        cleaned[name] = value
    return cleaned


def semantic_signature(tool_id: Any, arguments: Mapping[str, Any] | None) -> str:
    """Stable SHA-256 of ``(tool, semantic arguments)``."""
    payload = json.dumps(
        [str(tool_id or ""), semantic_arguments(arguments)],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
