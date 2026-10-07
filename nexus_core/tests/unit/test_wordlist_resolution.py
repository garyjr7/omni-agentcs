"""Fase 4.0: wordlists resolve from the workspace or a system wordlist dir.

The wordlist path comes from the model, so it stays confined. The E2E #5 failed
three iterations because the installed Kali wordlists live outside the
workspace; the allowlist of read-only system dirs keeps the boundary while
letting the agent use a real wordlist.
"""

from __future__ import annotations

import pytest

from nexus_core.tools.handlers import ffuf


@pytest.fixture()
def _system_dir(tmp_path, monkeypatch):
    system = tmp_path / "system-wordlists"
    system.mkdir()
    (system / "common.txt").write_text("admin\nlogin\n")
    monkeypatch.setattr(ffuf, "system_wordlist_dirs", lambda: (system.resolve(),))
    return system


def test_wordlist_inside_the_workspace_is_accepted(tmp_path, _system_dir):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    wordlist = workspace / "words.txt"
    wordlist.write_text("a\n")

    assert ffuf.resolve_wordlist(workspace, "words.txt") == str(wordlist.resolve())


def test_wordlist_in_an_allowlisted_system_dir_is_accepted(tmp_path, _system_dir):
    workspace = tmp_path / "ws"
    workspace.mkdir()

    resolved = ffuf.resolve_wordlist(workspace, str(_system_dir / "common.txt"))

    assert resolved == str((_system_dir / "common.txt").resolve())


def test_path_outside_both_roots_is_refused(tmp_path, _system_dir):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("nope")

    with pytest.raises(ValueError, match="must live inside the workspace"):
        ffuf.resolve_wordlist(workspace, str(outside))


def test_traversal_escape_is_refused(tmp_path, _system_dir):
    workspace = tmp_path / "ws"
    workspace.mkdir()

    with pytest.raises(ValueError):
        ffuf.resolve_wordlist(workspace, "../../etc/passwd")


def test_missing_wordlist_in_an_allowed_root_is_refused(tmp_path, _system_dir):
    workspace = tmp_path / "ws"
    workspace.mkdir()

    with pytest.raises(ValueError, match="does not exist"):
        ffuf.resolve_wordlist(workspace, str(_system_dir / "missing.txt"))
