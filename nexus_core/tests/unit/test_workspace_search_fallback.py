"""Fase 4.0: ``nexus.workspace.search`` works without ripgrep.

``rg`` was hardcoded; the E2E #5 host ships GNU grep but not ripgrep, so the tool
failed with ``No such file or directory: 'rg'``. The argv builder now prefers
ripgrep and falls back to grep with the same empty-result contract.
"""

from __future__ import annotations

import pytest

from nexus_core.tools.handlers.workspace import search_argv


def test_rg_argv_when_ripgrep_is_chosen():
    argv = search_argv("locks", program="rg")

    assert argv[0] == "rg"
    assert argv[-2] == "locks"


def test_grep_argv_when_grep_is_chosen():
    argv = search_argv("locks", program="grep")

    assert argv[0] == "grep"
    assert "-rn" in argv
    assert argv[-2] == "locks"


def test_default_prefers_rg_when_present(monkeypatch):
    monkeypatch.setattr(
        "nexus_core.tools.handlers.workspace.shutil.which",
        lambda name: "/usr/bin/rg" if name == "rg" else None,
    )

    assert search_argv("x")[0] == "rg"


def test_default_falls_back_to_grep_when_rg_absent(monkeypatch):
    monkeypatch.setattr("nexus_core.tools.handlers.workspace.shutil.which", lambda name: None)

    assert search_argv("x")[0] == "grep"


@pytest.mark.asyncio
async def test_handler_falls_back_to_grep_when_rg_disappears(monkeypatch):
    """A FileNotFoundError on the chosen binary retries with the other one."""
    calls: list[list[str]] = []

    class _FakeResult:
        exit_code = 0
        stdout = "match"
        stderr = ""
        timed_out = False

    class _FakeSandbox:
        async def run(self, argv, **kwargs):
            calls.append(list(argv))
            if argv[0] == "rg":
                raise FileNotFoundError("rg")
            return _FakeResult()

    monkeypatch.setattr(
        "nexus_core.tools.handlers.workspace.shutil.which",
        lambda name: "/usr/bin/rg" if name == "rg" else None,
    )
    monkeypatch.setattr(
        "nexus_core.tools.handlers.workspace.sandbox_for_environment",
        lambda *a, **k: _FakeSandbox(),
    )

    from nexus_core.tools.handlers.workspace import workspace_search_handler

    result = await workspace_search_handler({"query": "x"}, None)

    assert [argv[0] for argv in calls] == ["rg", "grep"]
    assert result.verified is True
    assert result.output["program"] == "grep"
