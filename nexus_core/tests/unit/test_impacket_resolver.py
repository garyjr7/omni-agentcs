"""Unit tests for the impacket binary resolver."""

from __future__ import annotations

import shutil

import pytest

from nexus_core.tools.handlers._impacket_resolver import resolve_impacket_binary

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_cache():
    resolve_impacket_binary.cache_clear()
    yield
    resolve_impacket_binary.cache_clear()


def test_resolve_finds_impacket_kali_style(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/usr/bin/impacket-secretsdump"
        if name == "impacket-secretsdump"
        else None,
    )
    assert resolve_impacket_binary("secretsdump") == "/usr/bin/impacket-secretsdump"


def test_resolve_finds_pip_style(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/home/u/.local/bin/secretsdump.py"
        if name == "secretsdump.py"
        else None,
    )
    assert resolve_impacket_binary("secretsdump") == "/home/u/.local/bin/secretsdump.py"


def test_resolve_prefers_kali_over_pip(monkeypatch):
    seen: list[str] = []

    def which(name):
        seen.append(name)
        return {"impacket-secretsdump": "/usr/bin/impacket-secretsdump"}.get(name)

    monkeypatch.setattr(shutil, "which", which)
    assert resolve_impacket_binary("secretsdump") == "/usr/bin/impacket-secretsdump"
    assert seen == ["impacket-secretsdump"]


def test_resolve_falls_back_to_bare_name(monkeypatch):
    monkeypatch.setattr(
        shutil, "which", lambda name: "/opt/bin/psexec" if name == "psexec" else None
    )
    assert resolve_impacket_binary("psexec") == "/opt/bin/psexec"


def test_resolve_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert resolve_impacket_binary("GetUserSPNs") is None
