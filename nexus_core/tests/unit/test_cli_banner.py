"""Banner: ASCII art, live stats, audit marker and deterministic tips."""

from __future__ import annotations

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
    values = {
        **STATS,
        "width": 100,
        "include_tip": False,
        "no_color": True,
        **overrides,
    }
    return build_banner(**values)


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
    text = build_banner(width=100, include_tip=False, **STATS)
    assert "\033[" in text
    assert "engagement: scanme-lab" in _plain(text)
    assert "OmniAgentCS v3.0.0" in _plain(text)
    assert "audit-chain ✓" in _plain(text)


def test_pick_tip_returns_from_list():
    assert pick_tip() in banner_module.TIPS


def test_pick_tip_deterministic_with_seed(monkeypatch):
    monkeypatch.setenv("NEXUS_TIP_SEED", "0")
    first = pick_tip()
    assert first == pick_tip()
    assert first == banner_module.TIPS[0]
    monkeypatch.setenv("NEXUS_TIP_SEED", str(len(banner_module.TIPS) + 3))
    assert pick_tip() == banner_module.TIPS[3]