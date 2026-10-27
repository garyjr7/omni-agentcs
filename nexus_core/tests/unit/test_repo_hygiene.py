"""SEC-08: engagement evidence must not keep entering the index.

The repository has 133 tracked files that are evidence from real engagements
(``docs/missions/salas/``, ``docs/missions/evidence/``) plus one password hash
dump, and the audit marks publishing them as a blocking finding. Removing them
from the index is the operator's call — it rewrites what the report cites — so
this test does not touch the index: it freezes today's list and fails when a
**new** path appears, which is the failure a CI gate can actually prevent.

The baseline may only shrink. ``docs/missions/audit-v1/evidence-index-baseline.txt``
carries the reason and the removal procedure.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BASELINE_PATH = REPO_ROOT / "docs" / "missions" / "audit-v1" / "evidence-index-baseline.txt"
#: Directories that hold engagement evidence and never belong in a release.
EVIDENCE_DIRS = ("docs/missions/salas/", "docs/missions/evidence/")


def _tracked_files() -> list[str]:
    """Return the index contents, or skip when git cannot answer.

    A wheel install has no ``.git``: there is no index to check and the guard
    has nothing to protect, so it skips instead of failing for the wrong reason.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files"],
            capture_output=True, text=True, check=True, timeout=60,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pytest.skip("git is not available to read the index")
    return [line for line in completed.stdout.splitlines() if line]


def _baseline() -> set[str]:
    return {
        line.strip()
        for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _is_evidence(path: str) -> bool:
    return path.startswith(EVIDENCE_DIRS) or path.endswith(".hash")


def test_no_new_engagement_evidence_enters_the_index():
    """A new lab dump or ``*.hash`` in the index stops the build."""
    tracked = {path for path in _tracked_files() if _is_evidence(path)}
    if not tracked:
        pytest.skip("no git index to inspect")
    baseline = _baseline()
    new = sorted(tracked - baseline)
    assert not new, (
        "evidencia de engagement nueva en el índice (SEC-08): "
        f"{new}. Sácala del índice; no la añadas a "
        f"{BASELINE_PATH.relative_to(REPO_ROOT)}."
    )


def test_the_baseline_lists_only_evidence_paths():
    """A garbage line would silently whitelist a path that is not evidence."""
    baseline = _baseline()
    assert baseline
    assert not sorted(path for path in baseline if not _is_evidence(path))
