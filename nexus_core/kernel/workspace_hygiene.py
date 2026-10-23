"""Workspace isolation check: does the run start with the answers on disk?

The measured problem
--------------------
``docs/missions/diag/deaddrop_campaign_2026-10-22.md`` was written **nine hours
before** run v3b and contained the flag, the NTLM hash of ``Administrator`` and
the exact recipe (``secretsdump → hash → wmiexec → type flag.txt``). The run's own
``shell.exec`` greps the workspace by design, so the string the model "found"
between iterations 71 and 76 was byte-identical to one already written in its own
working directory. Nothing in that record can tell discovery from recall, and a
pentest whose report is on the desk is not a pentest.

What this check is (and is not)
-------------------------------
It is a **pre-flight warning for the operator**, not a sandbox: it never deletes,
moves or blocks anything, and it never tells the model where the answers are (a
prompt that names them is an invitation). It answers one question, in the two
places an operator actually looks -``omni --doctor`` before the run and
``nexus.system.status`` during it:

    is this workspace clean enough for the run to be able to certify discovery?

The scan is deliberately narrow (``docs/missions``, ``loot``, ``notes``,
``writeups``; ``.md``/``.txt``) and bounded, so a workspace full of wordlists or
tool output costs one directory walk and not a byte-for-byte read of the disk.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

#: Directories (relative to the workspace) where an answer sheet would live.
SPOILER_DIRECTORIES: tuple[str, ...] = ("docs/missions", "loot", "notes", "writeups")

#: Files that carry prose: a binary or a wordlist is not a walkthrough.
SPOILER_SUFFIXES: tuple[str, ...] = (".md", ".txt")

#: Words that name an answer sheet. ``flag``/``password`` are what the DeadDrop
#: document had in its body, not only in its name.
SPOILER_WORDS: tuple[str, ...] = (
    "walkthrough",
    "writeup",
    "write-up",
    "cheat sheet",
    "cheatsheet",
    "flag",
    "password",
    "contraseña",
    "contrasena",
    "solución",
    "solucion",
)

#: A captured flag is an answer on its own, whatever the prose says.
SPOILER_FLAG_RE = re.compile(r"(?:THM|HTB|CTF|FLAG)\{[^}\s]{4,200}\}")

#: Caps. The scan is a pre-flight check, never a full-text index of the disk.
MAX_FILES_EXAMINED = 400
MAX_DIRECTORY_ENTRIES = 2_000
MAX_HEAD_BYTES = 32_768
MAX_REPORTED = 5


@dataclass(frozen=True)
class SpoilerScan:
    """What one scan found: where it looked and which files look like answers."""

    root: str
    files: tuple[str, ...]
    total: int

    @property
    def contaminated(self) -> bool:
        """Whether the workspace holds at least one suspected answer sheet."""
        return self.total > 0

    def to_dict(self) -> dict:
        """Report fragment: paths and count, never content."""
        return {
            "workspace": self.root,
            "workspace_spoilers": list(self.files),
            "workspace_spoiler_count": self.total,
        }


def workspace_root() -> str:
    """The directory the durable handlers treat as the workspace.

    Same variable ``tools.handlers.workspace.workspace_root`` reads. It is
    re-read here instead of imported because the kernel must not depend on the
    tool layer (the handlers already import from the kernel, not the reverse).
    """
    return os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())


def _looks_like_answers(path: Path) -> bool:
    """Whether one file is named like, or opens like, an answer sheet."""
    stem = path.stem.lower()
    if any(word in stem for word in SPOILER_WORDS):
        return True
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(MAX_HEAD_BYTES)
    except OSError:
        return False
    lowered = head.lower()
    if any(word in lowered for word in SPOILER_WORDS):
        return True
    return bool(SPOILER_FLAG_RE.search(head))


def scan_spoilers(root: str | Path | None = None) -> SpoilerScan:
    """Return the answer sheets found under the workspace's spoiler directories."""
    root_path = Path(root or workspace_root()).expanduser().resolve()
    if not root_path.is_dir():
        return SpoilerScan(str(root_path), (), 0)
    found: list[str] = []
    total = examined = seen = 0
    for name in SPOILER_DIRECTORIES:
        base = root_path / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            seen += 1
            if seen > MAX_DIRECTORY_ENTRIES or examined >= MAX_FILES_EXAMINED:
                break
            if not path.is_file() or path.suffix.lower() not in SPOILER_SUFFIXES:
                continue
            relative = path.relative_to(root_path)
            if any(part.startswith(".") for part in relative.parts):
                # Sandbox plumbing (``.sandbox_home``) is not agent-visible.
                continue
            examined += 1
            if not _looks_like_answers(path):
                continue
            total += 1
            if len(found) < MAX_REPORTED:
                found.append(str(relative))
        if seen > MAX_DIRECTORY_ENTRIES or examined >= MAX_FILES_EXAMINED:
            break
    return SpoilerScan(str(root_path), tuple(found), total)


def spoiler_report(root: str | Path | None = None) -> dict:
    """``{}`` when the workspace is clean, else the scan as report fields.

    Empty when clean so no caller pays for a key that says "nothing to see".
    """
    scan = scan_spoilers(root)
    if not scan.contaminated:
        return {}
    return scan.to_dict()


__all__ = [
    "MAX_FILES_EXAMINED",
    "MAX_REPORTED",
    "SPOILER_DIRECTORIES",
    "SPOILER_FLAG_RE",
    "SPOILER_SUFFIXES",
    "SPOILER_WORDS",
    "SpoilerScan",
    "scan_spoilers",
    "spoiler_report",
    "workspace_root",
]
