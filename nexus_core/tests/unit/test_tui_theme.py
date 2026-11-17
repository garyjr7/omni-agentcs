"""The palette has one owner: renderers must not carry hex literals."""

import inspect
import re

from nexus_core.cli import theme
from nexus_core.cli.tui import layout, panels, presentation, status


def test_renderers_delegate_colours_to_the_theme() -> None:
    hex_literal = re.compile(r"#[0-9a-fA-F]{6}")
    for module in (presentation, layout, panels, status):
        source = inspect.getsource(module)
        assert not hex_literal.search(source), module.__name__


def test_theme_exposes_the_semantic_roles() -> None:
    for role in ("primary", "surface", "surface_alt", "text", "muted", "thinking",
                 "ok", "error", "warn", "subtle"):
        assert getattr(theme.THEME, role)
    assert theme.THEME.panel_style == f"bg:{theme.THEME.surface}"
    assert theme.THEME.panel_bar_style == f"fg:{theme.THEME.primary} bg:{theme.THEME.surface}"


def test_reasoning_is_muted_italic_and_the_result_uses_a_surface() -> None:
    assert theme.THEME.thinking_style == f"{theme.THEME.muted} italic"
    assert theme.THEME.keycap_style == f"{theme.THEME.muted} on {theme.THEME.surface}"
    # Cards sit one step lighter than the screen background, never black-on-black.
    assert theme.THEME.result_panel_style == f"on {theme.THEME.surface}"
    assert theme.THEME.app_background_style == f"bg:{theme.THEME.surface_alt}"
    assert theme.THEME.result_border_style == theme.THEME.frame_border
    assert theme.THEME.frame_border_style == theme.THEME.frame_border


def test_compatibility_ansi_tokens_are_derived_from_the_theme() -> None:
    assert theme.RED == theme.ansi(theme.THEME.error)
    assert theme.GREEN == theme.ansi(theme.THEME.ok)
    assert theme.YELLOW == theme.ansi(theme.THEME.warn)
