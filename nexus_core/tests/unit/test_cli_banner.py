"""Banner: compact branded header by default, big ASCII art on demand."""

from __future__ import annotations

import os
import re

import pytest

from nexus_core.cli import banner as banner_module
from nexus_core.cli import render
from nexus_core.cli.banner import build_banner, pick_tip

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _plain(text: str) -> str:
    """Text as it looks on a terminal (ANSI codes removed)."""
    return _ANSI_RE.sub("", text)

STATS = dict(
    version="3.0.0",
    tools_count=16,
    providers_count=7,
    engagement_name="scanme-lab",
    audit_chain_valid=True,
    msfrpcd_version="6.5.3",
    llm_summary="groq/openai/gpt-oss-20b",
)


@pytest.fixture(autouse=True)
def _color():
    """Deterministic colour state for every test in this module."""
    render.configure_color(no_color=True)
    yield
    render.configure_color(no_color=False)


def _banner(**overrides) -> str:
    """The legacy big ASCII banner (``compact=False``, used by ``--about``)."""
    values = {
        **STATS,
        "width": 100,
        "include_tip": False,
        "no_color": True,
        "compact": False,
        **overrides,
    }
    return build_banner(**values)


def _header(**overrides) -> str:
    """The compact three-line header shown at REPL startup (default)."""
    values = {
        "version": "3.0.0",
        "engagement_name": "scanme-lab",
        "scope_summary": "1 CIDR · 1 dominio · 0 URLs",
        "valid_until": "2026-10-07T14:00:00Z",
        "sandbox_mode": "local_strict",
        "audit_chain_valid": True,
        "width": 100,
        "include_tip": False,
        "no_color": True,
        **overrides,
    }
    return build_banner(
        tools_count=16,
        providers_count=7,
        msfrpcd_version="6.5.3",
        llm_summary="groq/openai/gpt-oss-20b",
        **values,
    )


# --------------------------------------------------------------- compact header
def test_header_shows_branding_and_team_red():
    text = _header()
    assert banner_module.BRAND in text  # BAJIOWARE
    assert "Team Red ◈" in text
    assert "OMNIAGENTCS" in text


def test_header_shows_engagement_scope_and_validity():
    text = _header()
    assert "scanme-lab" in text
    assert "1 CIDR · 1 dominio · 0 URLs" in text
    assert "2026-10-07T14:00:00Z" in text


def test_header_shows_sandbox_mode_and_audit_ok():
    text = _header()
    assert "local_strict" in text
    assert "audit ok" in text


def test_header_audit_invalid_marker():
    assert "audit INVALID" in _header(audit_chain_valid=False)


def test_header_no_engagement_is_explicit():
    assert "sin engagement" in _header(engagement_name=None)


def test_header_has_no_ascii_art():
    assert "██████╗" not in _header()


def test_header_follows_narrow_terminal_when_width_unspecified(monkeypatch):
    """A 60-column terminal must not wrap the compact header."""
    monkeypatch.setattr(
        banner_module.shutil,
        "get_terminal_size",
        lambda *args, **kwargs: os.terminal_size((60, 24)),
    )
    text = _header(width=None)
    assert max(len(line) for line in text.splitlines()) <= 60


def test_header_never_grows_past_designed_width(monkeypatch):
    monkeypatch.setattr(
        banner_module.shutil,
        "get_terminal_size",
        lambda *args, **kwargs: os.terminal_size((200, 50)),
    )
    text = _header(width=None)
    assert max(len(line) for line in text.splitlines()) <= banner_module.DEFAULT_HEADER_WIDTH


def test_header_compact_by_default():
    assert "██████╗" not in build_banner(**_header_values_no_compact())


def _header_values_no_compact():
    return {
        "version": "3.0.0",
        "tools_count": 16,
        "providers_count": 7,
        "engagement_name": "scanme-lab",
        "audit_chain_valid": True,
        "msfrpcd_version": "6.5.3",
        "llm_summary": "groq/openai/gpt-oss-20b",
        "width": 100,
        "include_tip": False,
        "no_color": True,
    }


# --------------------------------------------------------------- legacy art
def test_banner_contains_ascii_art():
    text = _banner()
    assert "██████╗" in text
    assert "A G E N T C S" in text
    assert "C L I" in text


def test_banner_contains_version():
    assert "OmniAgentCS v3.0.0" in _banner()
    assert "OmniAgentCS v9.9.9" in _banner(version="9.9.9")


def test_banner_contains_tools_count():
    text = _banner()
    assert "16 tools" in text
    assert "7 providers" in text


def test_banner_contains_engagement_name_when_set():
    assert "engagement: scanme-lab" in _banner()


def test_banner_shows_none_when_no_engagement():
    assert "engagement: none" in _banner(engagement_name=None)
    assert "engagement: none" in _banner(engagement_name="")


def test_banner_audit_chain_valid_checkmark():
    render.configure_color(no_color=False)
    text = _banner(no_color=False)
    assert "audit-chain ✓" in _plain(text)


def test_banner_audit_chain_invalid_x():
    render.configure_color(no_color=False)
    text = _banner(no_color=False, audit_chain_valid=False)
    assert "audit-chain ✗" in _plain(text)
    # Plain mode never emits the non-ASCII marker.
    assert "audit-chain INVALID" in _banner(audit_chain_valid=False)


def test_banner_msfrpcd_version_when_available():
    assert "msfrpcd 6.5.3" in _banner()


def test_banner_msfrpcd_na_when_unavailable():
    assert "msfrpcd n/a" in _banner(msfrpcd_version=None)
    assert "msfrpcd n/a" in _banner(msfrpcd_version="")


def test_banner_narrow_terminal_omits_art():
    narrow = _banner(width=banner_module.MIN_WIDTH_FOR_ART - 1)
    assert "██████╗" not in narrow
    assert "A G E N T C S" not in narrow
    # The stats block survives: the banner is still useful on a small terminal.
    assert "16 tools" in narrow
    assert "audit-chain ok" in narrow


def test_banner_wide_terminal_keeps_art():
    assert "██████╗" in _banner(width=banner_module.MIN_WIDTH_FOR_ART)


def test_banner_no_color_emits_no_ansi():
    """The global colour state must not leak ANSI into a plain banner."""
    render.configure_color(no_color=False)
    text = _banner(engagement_name=None, msfrpcd_version=None)
    assert "\033[" not in text


def test_banner_with_color_emits_ansi_but_keeps_plain_tokens():
    render.configure_color(no_color=False)
    text = build_banner(width=100, include_tip=False, compact=False, **STATS)
    assert "\033[" in text
    assert "engagement: scanme-lab" in _plain(text)
    assert "OmniAgentCS v3.0.0" in _plain(text)
    assert "audit-chain ✓" in _plain(text)


def test_header_with_color_emits_ansi_but_keeps_plain_tokens():
    render.configure_color(no_color=False)
    text = _header(no_color=False)
    assert "\033[" in text
    assert "BAJIOWARE" in _plain(text)
    assert "Team Red ◈" in _plain(text)
    assert "scanme-lab" in _plain(text)
    assert "audit ✓ ok" in _plain(text)


def test_pick_tip_returns_from_list():
    assert pick_tip() in banner_module.TIPS


def test_pick_tip_deterministic_with_seed(monkeypatch):
    monkeypatch.setenv("NEXUS_TIP_SEED", "0")
    first = pick_tip()
    assert first == pick_tip()
    assert first == banner_module.TIPS[0]
    monkeypatch.setenv("NEXUS_TIP_SEED", str(len(banner_module.TIPS) + 3))
    assert pick_tip() == banner_module.TIPS[3]
