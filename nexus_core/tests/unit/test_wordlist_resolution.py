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


def test_a_missing_wordlist_names_the_lists_that_are_installed(tmp_path, _system_dir):
    """hijack_v7 invented ``path/to/passwords.txt`` twice at the brute force.

    The rejection said only that the invented path did not exist, so the next
    attempt invented another one. It now carries the real files on this host.
    """
    (tmp_path / "system-wordlists" / "rockyou.txt").write_text("admin\n")
    workspace = tmp_path / "ws"
    workspace.mkdir()

    with pytest.raises(ValueError) as excinfo:
        ffuf.resolve_wordlist(workspace, "path/to/passwords.txt")
    message = str(excinfo.value)
    assert "path/to/passwords.txt" in message
    assert "rockyou.txt" in message


def test_the_default_wordlist_is_the_first_installed_one(tmp_path):
    from nexus_core.tools import wordlists

    system = tmp_path / "wordlists"
    system.mkdir()
    assert wordlists.default_wordlist([system]) is None
    (system / "rockyou.txt").write_text("admin\n")
    assert wordlists.default_wordlist([system]) == str(system / "rockyou.txt")
